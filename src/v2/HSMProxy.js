/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
'use strict';

/*
 * This class implements a proxy to a remote hardware security module that is capable of
 * performing the following functions:
 * <pre>
 *   * generateKeys - generate a new public-private key pair and return the public key
 *   * digestBytes - generate a cryptographic digest of an array of bytes
 *   * signBytes - digitally sign an array of bytes using the private key
 *   * validSignature - check whether or not the digital signature of an array of bytes is valid
 *   * rotateKeys - replace the existing public-private key pair with new pair
 *   * eraseKeys - erases any trace of the public-private key pair
 * </pre>
 */
const crypto = require('crypto');
const bluetooth = require('@abandonware/noble');
const bali = require('bali-component-framework').api();


// PRIVATE CONSTANTS

// the POSIX end of line character
const EOL = '\n';

// the algorithms for this version of the protocol
const PROTOCOL = 'v2';
const DIGEST = 'sha512';
const SIGNATURE = 'ed25519';

// byte array sizes
const KEY_SIZE = 32;  // bytes
const BLOCK_SIZE = 510;  // the maximum MTU size minus the two header bytes

// these are viewed from the client (mobile device) perspective
const UART_SERVICE_ID = '6e400001b5a3f393e0a9e50e24dcca9e';
const UART_WRITE_ID = '6e400002b5a3f393e0a9e50e24dcca9e';
const UART_NOTIFICATION_ID = '6e400003b5a3f393e0a9e50e24dcca9e';

// define the finite state machine
const REQUESTS = [  //     possible request types
              '$generateKeys', '$signBytes', '$rotateKeys'
];
const STATES = {
//   current                allowed next states
    $keyless: [ '$loneKey',      undefined,    undefined  ],
    $loneKey: [  undefined,     '$loneKey',   '$twoKeys'  ],
    $twoKeys: [  undefined,     '$loneKey',    undefined  ]
};


// PUBLIC FUNCTIONS

/**
 * This function creates a new instance of a remote hardware security module (HSM) proxy.
 *
 * @param {String} directory An optional directory to be used for local configuration storage. If
 * no directory is specified, a directory called '.bali/' is created in the home directory.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls the level of
 * debugging that occurs:
 * <pre>
 *   0 (or false): no logging
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} The new hardware security module proxy.
 */
const HSMProxy = function(directory, debug) {

    // validate the arguments
    if (debug === null || debug === undefined) debug = 0;  // default is off
    if (debug > 1) {
        const validator = bali.validator(debug);
        validator.validateType('/bali/notary/' + PROTOCOL + '/HSMProxy', '$HSMProxy', '$directory', directory, [
            '/javascript/Undefined',
            '/javascript/String'
        ]);
    }


    // PRIVATE CONFIGURATION ATTRIBUTES AND METHODS

    const filename = 'HSMProxy' + PROTOCOL + '.bali';
    const configurator = bali.configurator(filename, directory, debug);
    var configuration, controller;

    const loadConfiguration = async function() {
        try {
            const source = await configurator.load();
            if (source) {
                configuration = bali.component(source);
            } else {
                configuration = bali.catalog({
                    $tag: bali.tag(),  // new random tag
                    $state: '$keyless'
                });
                await configurator.store(configuration.toString() + EOL);
            }
            controller = bali.controller(REQUESTS, STATES, configuration.getValue('$state').toString(), debug);
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$loadConfiguration',
                $exception: '$storageException',
                $text: 'The attempt to load the current configuration failed.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    const storeConfiguration = async function() {
        try {
            await configurator.store(configuration.toString() + EOL);
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$storeConfiguration',
                $exception: '$storageException',
                $text: 'The attempt to store the current configuration failed.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    const deleteConfiguration = async function() {
        try {
            await configurator.delete();
            configuration = undefined;
            controller = undefined;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$deleteConfiguration',
                $exception: '$storageException',
                $text: 'The attempt to delete the current configuration failed.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };


    // PUBLIC METHODS

    /**
     * This method returns a string describing the attributes of the HSM. It must not be an
     * asynchronous function since it is part of the JavaScript language.
     * 
     * @returns {String} A string describing the attributes of the HSM.
     */
    this.toString = function() {
        const catalog = bali.catalog({
            $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
            $protocol: PROTOCOL,
            $digest: DIGEST,
            $signature: SIGNATURE
        });
        return catalog.toString();
    };

    /**
     * This method returns the unique tag for the security module.
     * 
     * @returns {Tag} The unique tag for the security module.
     */
    this.getTag = async function() {
        try {
            // load the current configuration if necessary
            if (!configuration) await loadConfiguration();

            return configuration.getValue('$tag');
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$getTag',
                $exception: '$unexpected',
                $text: 'The tag for the security module could not be retrieved.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };


    /**
     * This method returns the version of the security protocol supported by this
     * security module.
     * 
     * @returns {Version} The version string of the security protocol supported by this security
     * module.
     */
    this.getProtocol = async function() {
        try {
            return bali.component(PROTOCOL);
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$getProtocol',
                $exception: '$unexpected',
                $text: 'The protocol supported by the security module could not be retrieved.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method generates a new public-private key pair.
     * 
     * @returns {Binary} A binary string containing the new public key.
     */
    this.generateKeys = async function() {
        try {
            // check the current state
            if (!configuration) await loadConfiguration();
            controller.validateEvent('$generateKeys');

            // generate a new key pair
            if (debug > 2) console.log("\nGenerating the initial key pair...");
            const proxyKey = bali.binary(crypto.randomBytes(KEY_SIZE));
            const request = formatRequest('generateKeys', proxyKey.getValue());
            const publicKey = bali.binary(await processRequest(request, debug));
            configuration.setValue('$proxyKey', proxyKey);

            // update the configuration
            const state = controller.transitionState('$generateKeys');
            configuration.setValue('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            if (debug > 2) console.log('public key: ' + publicKey);
            return publicKey;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$generateKeys',
                $exception: '$unexpected',
                $text: 'A new key pair could not be generated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method replaces the existing public-private key pair with a new one.
     * 
     * @returns {Binary} A binary string containing the new public key.
     */
    this.rotateKeys = async function() {
        try {
            // check the current state
            if (!configuration) await loadConfiguration();
            controller.validateEvent('$rotateKeys');

            // save the previous proxy key
            const previousProxyKey = configuration.getValue('$proxyKey');
            configuration.setValue('$previousProxyKey', previousProxyKey);

            // generate a new key pair
            if (debug > 2) console.log("\nGenerating a new key pair...");
            const proxyKey = bali.binary(crypto.randomBytes(KEY_SIZE));
            const request = formatRequest('rotateKeys', previousProxyKey.getValue(), proxyKey.getValue());
            const publicKey = bali.binary(await processRequest(request, debug));
            configuration.setValue('$proxyKey', proxyKey);

            // update the configuration
            const state = controller.transitionState('$rotateKeys');
            configuration.setValue('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            if (debug > 2) console.log('public key: ' + publicKey);
            return publicKey;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$rotateKeys',
                $exception: '$unexpected',
                $text: 'The key pair could not be rotated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method deletes any existing public-private key pairs.
     * 
     * @returns {Boolean} Whether or not the keys were successfully erased.
     */
    this.eraseKeys = async function() {
        try {
            // erase the keys on the remote hardware security module
            if (debug > 2) console.log("\nErasing all key pairs...");
            const request = formatRequest('eraseKeys');
            const succeeded = (await processRequest(request, debug))[0] ? true : false;

            // delete the current configuration
            await deleteConfiguration(configurator, debug);
            configuration = undefined;

            if (debug > 2) console.log("succeeded: " + succeeded);
            return succeeded;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$eraseKeys',
                $exception: '$unexpected',
                $text: 'The keys could not be erased.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method returns a cryptographically secure digital digest of the
     * specified bytes. The generated digital digest will always be the same
     * for the same bytes.
     *
     * @param {Buffer} bytes The bytes to be digested.
     * @returns {Binary} A binary string containing a digital digest of the bytes.
     */
    this.digestBytes = async function(bytes) {
        try {
            // validate the arguments
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/' + PROTOCOL + '/HSMProxy', '$digestBytes', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }

            // generate the digital digest of the bytes
            if (debug > 2) console.log("\nDigesting the bytes...");
            const request = formatRequest('digestBytes', bytes);
            const digest = bali.binary(await processRequest(request, debug));

            if (debug > 2) console.log('digest: ' + digest);
            return digest;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$digestBytes',
                $exception: '$unexpected',
                $text: 'A digest of the bytes could not be generated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method generates a digital signature of the specified bytes using
     * the current private key (or the old private key, one time only, if it exists).
     * This allows a new certificate to be signed using the previous private key.
     * The resulting digital signature can then be verified using the corresponding
     * public key.
     * 
     * @param {Buffer} bytes The bytes to be digitally signed.
     * @returns {Binary} A binary string containing the resulting digital signature.
     */
    this.signBytes = async function(bytes) {
        try {
            // validate the arguments
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/' + PROTOCOL + '/HSMProxy', '$signBytes', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }

            // check the current state
            if (!configuration) await loadConfiguration();
            controller.validateEvent('$signBytes');
            if (debug > 2) console.log("\nSigning the bytes...");

            // retrieve the proxy key
            var proxyKey = configuration.removeValue('$previousProxyKey');
            if (!proxyKey) {
                proxyKey = configuration.getValue('$proxyKey');
            }

            // digitally sign the bytes using the private key
            const request = formatRequest('signBytes', proxyKey.getValue(), bytes);
            const signature = bali.binary(await processRequest(request, debug));

            // update the configuration
            const state = controller.transitionState('$signBytes');
            configuration.setValue('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            if (debug > 2) console.log('signature: ' + signature);
            return signature;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$signBytes',
                $exception: '$unexpected',
                $text: 'A digital signature of the bytes could not be generated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method uses the specified public key to determine whether or not
     * the specified digital signature was generated using the corresponding
     * private key on the specified bytes.
     *
     * @param {Binary} aPublicKey A binary string containing the public key to be
     * used to validate the signature.
     * @param {Binary} signature A binary string containing the digital signature
     * allegedly generated using the corresponding private key.
     * @param {Buffer} bytes The digitally signed bytes.
     * @returns {Boolean} Whether or not the digital signature is valid.
     */
    this.validSignature = async function(aPublicKey, signature, bytes) {
        try {
            // validate the arguments
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/' + PROTOCOL + '/HSMProxy', '$validSignature', '$aPublicKey', aPublicKey, [
                    '/bali/elements/Binary'
                ]);
                validator.validateType('/bali/notary/' + PROTOCOL + '/HSMProxy', '$validSignature', '$signature', signature, [
                    '/bali/elements/Binary'
                ]);
                validator.validateType('/bali/notary/' + PROTOCOL + '/HSMProxy', '$validSignature', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }

            // check the signature on the bytes
            if (debug > 2) console.log("\nValidating the signature...");
            const request = formatRequest('validSignature', aPublicKey.getValue(), signature.getValue(), bytes);
            const isValid = (await processRequest(request, debug))[0] ? true : false;

            if (debug > 2) console.log("is valid: " + isValid);
            return isValid;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/HSMProxy',
                $procedure: '$validSignature',
                $exception: '$unexpected',
                $text: 'The digital signature of the bytes could not be validated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    return this;
};
HSMProxy.prototype.constructor = HSMProxy;
exports.HSMProxy = HSMProxy;


// PRIVATE FUNCTIONS

/**
 * This function formats a request into a binary format prior to sending it via bluetooth.
 * Each request has the following byte format:
 *   Request (1 byte) [0..255]
 *   Number of Arguments (1 byte) [0..255]
 *   Length of Argument 1 (2 bytes) [0..65535]
 *   Argument 1 ([0..65535] bytes)
 *   Length of Argument 2 (2 bytes) [0..65535]
 *   Argument 2 ([0..65535] bytes)
 *      ...
 *   Length of Argument N (2 bytes) [0..65535]
 *   Argument N ([0..65535] bytes)
 *
 * If the entire request is only a single byte long then the number of arguments
 * is assumed to be zero.

 * @param {String} type The type of the request.
 * @param {Buffer} args Zero or more buffers containing the bytes for each argument.
 * @returns {Buffer} A buffer containing the bytes for the entire request.
 */
const formatRequest = function(type, ...args) {
    switch (type) {
        case 'generateKeys':
            type = 1;
            break;
        case 'rotateKeys':
            type = 2;
            break;
        case 'eraseKeys':
            type = 3;
            break;
        case 'digestBytes':
            type = 4;
            break;
        case 'signBytes':
            type = 5;
            break;
        case 'validSignature':
            type = 6;
            break;
    }
    var request = Buffer.from([type & 0xFF, args.length & 0xFF]);
    args.forEach(arg => {
        var length = arg.length;
        request = Buffer.concat([
            request,                                               // the request thus far
            Buffer.from([(length & 0xFF00) >> 8, length & 0xFF]),  // the length of this argument
            arg],                                                  // the argument bytes
            request.length + length + 2                            // the length of the new buffer
        );
    });
    return request;
};


/**
 * This function sends a request to a BLEUart service for processing. The response is
 * returned from the service.  The function is asynchronous and returns a promise to
 * attempt to process the request.
 * 
 * Note: A BLEUart service can only handle requests up to 512 bytes in length. If the
 * specified request is longer than this limit, it is broken up into separate 512 byte
 * blocks and each block is sent as a separate BLE request.
 * 
 * @param {Buffer} request The request to be processed.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Promise} A promise to return the response from the service.
 */
const processRequest = async function(request, debug) {
    var tryAgain = 3;  // retry twice
    while (tryAgain--) {
        var peripheral;
        try {
            peripheral = await findPeripheral(debug);
            await connect(peripheral, debug);
            const service = await discoverService(peripheral, debug);
            const characteristics = await retrieveCharacteristics(service, debug);
            var input, output;
            characteristics.forEach (characteristic => {
                // TODO: make it more robust by checking properties instead of Ids
                if (characteristic.uuid === UART_NOTIFICATION_ID) input = characteristic;
                if (characteristic.uuid === UART_WRITE_ID) output = characteristic;
            });
            if (input && output) {
                if (debug > 2) console.log('Sending the request to the HSM...');
                // process any extra blocks in reverse order
                var buffer, offset, blockSize;
                var block = Math.ceil((request.length - 2) / BLOCK_SIZE) - 1;
                while (block > 0) {
                    // the offset includes the header bytes
                    offset = block * BLOCK_SIZE + 2;
            
                    // calculate the current block size
                    blockSize = Math.min(request.length - offset, BLOCK_SIZE);
            
                    // copy the request block into the buffer
                    buffer = request.slice(offset, offset + blockSize);
            
                    // prepend the header to the buffer
                    buffer = Buffer.concat([Buffer.from([0x00, block & 0xFF]), buffer], blockSize + 2);
    
                    await processBlock(input, output, buffer, debug);
                    if (debug > 2) console.log('A block was successfully sent to the HSM.');
                    block--;
                }

                // process the actual request
                blockSize = Math.min(request.length, BLOCK_SIZE + 2);
                buffer = request.slice(0, blockSize);
                const response = await processBlock(input, output, buffer, debug);
                if (debug > 2) console.log('A response was received from the HSM.');
                await disconnect(peripheral, debug);
                return response;
            } else {
                await disconnect(peripheral, debug);
                throw Error("The UART service doesn't support the right characteristics.");
            }
        } catch (cause) {
            if (tryAgain) {
                if (debug > 0) console.error('Request failed, trying again: ' + cause);
                if (peripheral) await disconnect(peripheral, debug);
                continue;
            }
            throw Error('Request failed too many times: ' + cause);
        }
    }
};


/**
 * This function searches for a bluetooth peripheral that implements the hardware security
 * module (HSM). Once one is found it stops searching. The function is asynchronous and
 * returns a promise to attempt to find the peripheral.
 * 
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Promise} A promise to return a matching peripheral.
 */
const findPeripheral = function(debug) {
    return new Promise(function(resolve, reject) {
        bluetooth.on('discover', function(peripheral) {
            const advertisement = peripheral.advertisement;
            if (debug > 2) console.log('Found ' + advertisement.localName + '.');
            if (advertisement.localName === 'ArmorD') {
                bluetooth.stopScanning();
                resolve(peripheral);
            }
        });
        setTimeout(function() {
            bluetooth.stopScanning();
            reject('No ArmorD™ found.');
        }, 1000);
        if (debug > 2) console.log('Searching for an ArmorD™...');
        bluetooth.startScanning([UART_SERVICE_ID]);  // start searching (asynchronously)
    });
};


const connect = function(peripheral, debug) {
    return new Promise(function(resolve, reject) {
        if (debug > 2) console.log('Attempting to connect to the HSM...');
        peripheral.connect(function(cause) {
            if (cause) {
                if (debug > 0) console.error('Failed to connect: ' + cause);
                reject(cause);
            } else {
                if (debug > 2) console.log('Successfully connected.');
                resolve();
            }
        });
    });
};


const disconnect = function(peripheral, debug) {
    return new Promise(function(resolve, reject) {
        if (debug > 2) console.log('Attempting to disconnect from the HSM...');
        peripheral.disconnect(function() {
            if (debug > 2) console.log('Disconnected from the HSM.');
            resolve();
        });
    });
};


const discoverService = function(peripheral, debug) {
    return new Promise(function(resolve, reject) {
        if (debug > 2) console.log('Attempting to discover the UART service...');
        peripheral.discoverServices([UART_SERVICE_ID], function(cause, services) {
            if (cause || services.length !== 1) {
                cause = cause || Error('Wrong number of UART services found: ' + services.length);
                reject(cause);
            } else {
                resolve(services[0]);
            }
        });
    });
};


const retrieveCharacteristics = function(service, debug) {
    return new Promise(function(resolve, reject) {
        if (debug > 2) console.log('Attempting to retrieve the UART characteristics...');
        service.discoverCharacteristics([], function(cause, characteristics) {
            if (cause) {
                reject(cause);
            } else {
                resolve(characteristics);
            }
        });
    });
};


/**
 * This function writes a block of bytes to the input characteristic of a BLEUart service
 * and reads the response from the output characteristic.  The function is asynchronous and
 * returns a promise to attempt to process the block of bytes.
 * 
 * @param {Characteristic} input The input characteristic for the BLEUart service.
 * @param {Characteristic} output The output characteristic for the BLEUart service.
 * @param {Buffer} block The block of bytes to be written.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Promise} A promise to return a buffer containing the bytes for the response from
 * the service.
 */
const processBlock = function(input, output, block, debug) {
    return new Promise(function(resolve, reject) {
        input.once('read', function(response, isNotification) {  // isNotification should always be true
            if (debug > 2) console.log('Read completed, ' + response.length + ' bytes read.');
            if (response.length === 1 && response.readUInt8(0) > 1) {
                if (debug > 2) console.log("response: " + response.readUInt8(0));
                reject('Processing of the block failed.');
            }
            resolve(response);
        });
        input.subscribe(function() {
            output.write(block, false, function() {
                if (debug > 2) console.log('Write completed, ' + block.length + ' bytes written.');
                // can't resolve it until the response is read
            });
        });
    });
};

