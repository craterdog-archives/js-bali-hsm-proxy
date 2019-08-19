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
 * This module uses the singleton pattern to provide an object that acts as a PROXY to
 * a hardware security module (HSM) for all cryptographic operations.  All cryptographic
 * operations are initiated via bluetooth and performed on the actual HSM.
 */
const crypto = require('crypto');
const bluetooth = require('@abandonware/noble');
const bali = require('bali-component-framework');


// PRIVATE CONSTANTS

// The algorithms for this version of the protocol
const PROTOCOL = 'v1';
const DIGEST = 'sha512';
const SIGNATURE = 'ed25519';
const BLOCK_SIZE = 510;  // the maximum MTU size minus the header bytes

// These are viewed from the client (mobile device) perspective
const UART_SERVICE_ID = '6e400001b5a3f393e0a9e50e24dcca9e';
const UART_WRITE_ID = '6e400002b5a3f393e0a9e50e24dcca9e';
const UART_NOTIFICATION_ID = '6e400003b5a3f393e0a9e50e24dcca9e';


// PUBLIC API

/**
 * This function returns a singleton object that implements the API for the hardware
 * security module (HSM).
 *
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} An object that implements the security module API.
 */
exports.api = function(debug) {
    debug = debug || false;
    var peripheral;
    var secret, previousSecret;

    return {

        /**
         * This function returns a string describing the attributes of the HSM.
         * 
         * @returns {String} A string describing the attributes of the HSM.
         */
        toString: function() {
            const string =
                '[\n' +
                '    $module: /bali/notary/' + PROTOCOL + '/HSMProxy\n' +
                '    $protocol: ' + PROTOCOL + '\n' +
                '    $digest: "' + DIGEST + '"\n' +
                '    $signature: "' + SIGNATURE + '"\n' +
                ']';
            return string;
        },

        /**
         * This function returns the version of the security protocol supported by this
         * security module.
         * 
         * @returns {String} The version of the security protocol supported by this security
         * module.
         */
        getProtocol: function() {
            return PROTOCOL;
        },

        /**
         * This function initializes the API.
         */
        initializeAPI: async function() {
            try {
                if (debug) console.log(new Date());
                peripheral = await findPeripheral(debug);
                this.initializeAPI = undefined;  // can only be called successfully once
                if (debug) console.log(new Date());
            } catch (cause) {
                const exception = bali.exception({
                    $module: '/bali/notary/v1/HSMProxy',
                    $procedure: '$initializeAPI',
                    $exception: '$unexpected',
                    $text: bali.text('The HSM could not be initialized.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function generates a new public-private key pair.
         * 
         * @returns {Buffer} A byte buffer containing the new public key.
         */
        generateKeys: async function() {
            try {
                if (debug) console.log(new Date());
                if (debug) console.log("\nGenerating the keys...");
                if (this.initializeAPI) await this.initializeAPI();
                secret = crypto.randomBytes(32);
                var request = formatRequest('generateKeys', secret);
                const publicKey = await processRequest(peripheral, request, debug);
                if (debug) console.log("public key: '" + bali.codex.base32Encode(publicKey, '    ') + "'");
                if (debug) console.log(new Date());
                return publicKey;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '/bali/notary/v1/HSMProxy',
                    $procedure: '$generateKeys',
                    $exception: '$unexpected',
                    $text: bali.text('A new key pair could not be generated.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },
        /**
         * This function replaces the existing public-private key pair with a new one.
         * 
         * @returns {Buffer} A byte buffer containing the new public key.
         */
        rotateKeys: async function() {
            try {
                if (debug) console.log(new Date());
                if (debug) console.log("\nRotating the keys...");
                if (this.initializeAPI) await this.initializeAPI();
                previousSecret = secret;
                secret = crypto.randomBytes(32);
                var request = formatRequest('rotateKeys', previousSecret, secret);
                const publicKey = await processRequest(peripheral, request, debug);
                if (debug) console.log("public key: '" + bali.codex.base32Encode(publicKey, '    ') + "'");
                if (debug) console.log(new Date());
                return publicKey;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '/bali/notary/v1/HSMProxy',
                    $procedure: '$rotateKeys',
                    $exception: '$unexpected',
                    $text: bali.text('A new key pair could not be generated.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function deletes any existing public-private key pairs.
         * 
         * @returns {Boolean} Whether or not the keys were successfully erased.
         */
        eraseKeys: async function() {
            try {
                if (debug) console.log(new Date());
                if (debug) console.log("\nErasing the keys...");
                if (this.initializeAPI) await this.initializeAPI();
                const request = formatRequest('eraseKeys');
                const succeeded = (await processRequest(peripheral, request, debug))[0] ? true : false;
                if (debug) console.log("succeeded: " + succeeded);
                if (debug) console.log(new Date());
                return succeeded;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '/bali/notary/v1/HSMProxy',
                    $procedure: '$eraseKeys',
                    $exception: '$unexpected',
                    $text: bali.text('The keys could not be erased.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function returns a cryptographically secure digital digest of the
         * specified bytes. The generated digital digest will always be the same
         * for the same bytes.
         *
         * @param {Buffer} bytes The bytes to be digested.
         * @returns {Buffer} A byte buffer containing a digital digest of the bytes.
         */
        digestBytes: async function(bytes) {
            try {
                if (debug) console.log(new Date());
                if (debug) console.log("\nDigesting bytes...");
                if (this.initializeAPI) await this.initializeAPI();
                const request = formatRequest('digestBytes', bytes);
                const digest = await processRequest(peripheral, request, debug);
                if (debug) console.log("digest: '" + bali.codex.base32Encode(digest, '    ') + "'");
                if (debug) console.log(new Date());
                return digest;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '/bali/notary/v1/HSMProxy',
                    $procedure: '$digestBytes',
                    $exception: '$unexpected',
                    $text: bali.text('A digest of the bytes could not be generated.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function generates a digital signature of the specified bytes using
         * the current private key (or the old private key, one time only, if it exists).
         * This allows a new certificate to be signed using the previous private key.
         * The resulting digital signature can then be verified using the corresponding
         * public key.
         * 
         * @param {Buffer} bytes The bytes to be digitally signed.
         * @returns {Buffer} A byte buffer containing the resulting digital signature.
         */
        signBytes: async function(bytes) {
            try {
                if (debug) console.log(new Date());
                if (debug) console.log("\nSigning bytes...");
                if (this.initializeAPI) await this.initializeAPI();
                var request;
                if (previousSecret) {
                    request = formatRequest('signBytes', previousSecret, bytes);
                    previousSecret = undefined;
                } else if (secret) {
                    request = formatRequest('signBytes', secret, bytes);
                } else {
                    throw Error('No keys exist.');
                }
                const signature = await processRequest(peripheral, request, debug);
                if (debug) console.log("signature: '" + bali.codex.base32Encode(signature, '    ') + "'");
                if (debug) console.log(new Date());
                return signature;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '/bali/notary/v1/HSMProxy',
                    $procedure: '$signBytes',
                    $exception: '$unexpected',
                    $text: bali.text('A digital signature of the bytes could not be generated.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function uses the specified public key to determine whether or not
         * the specified digital signature was generated using the corresponding
         * private key on the specified bytes.
         *
         * @param {Buffer} aPublicKey A byte buffer containing the public key to be
         * used to validate the signature.
         * @param {Buffer} signature A byte buffer containing the digital signature
         * allegedly generated using the corresponding private key.
         * @param {Buffer} bytes The digitally signed bytes.
         * @returns {Boolean} Whether or not the digital signature is valid.
         */
        validSignature: async function(aPublicKey, signature, bytes) {
            try {
                if (debug) console.log(new Date());
                if (debug) console.log("\nValidating a signature...");
                if (this.initializeAPI) await this.initializeAPI();
                var request = formatRequest('validSignature', aPublicKey, signature, bytes);
                const isValid = (await processRequest(peripheral, request, debug))[0] ? true : false;
                if (debug) console.log("is valid: " + isValid);
                if (debug) console.log(new Date());
                return isValid;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '/bali/notary/v1/HSMProxy',
                    $procedure: '$validSignature',
                    $exception: '$unexpected',
                    $text: bali.text('The digital signature of the bytes could not be validated.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        }

    };
};


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
            if (debug) console.log('Found ' + advertisement.localName + '.');
            if (advertisement.localName === 'ButtonUp') {
                bluetooth.stopScanning();
                resolve(peripheral);
            }
        });
        if (debug) console.log('Searching for an HSM...');
        bluetooth.startScanning([UART_SERVICE_ID]);  // start searching for an HSM (asynchronously)
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
        input.once('read', function(response, isNotification) {
            if (debug) console.log('Read completed, ' + response.length + ' bytes read.');
            if (response.length === 1 && response.readUInt8(0) > 1) {
                if (debug) console.log("response: " + response.readUInt8(0));
                reject('Processing of the block failed.');
            }
            resolve(response);
        });
        input.subscribe(function() {
            output.write(block, false, function() {
                if (debug) console.log('Write completed, ' + block.length + ' bytes written.');
                // can't resolve it until the response is read
            });
        });
    });
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
 * @param {Peripheral} peripheral The remote peripheral to do the processing.
 * @param {Buffer} request The request to be processed.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Promise} A promise to return the response from the service.
 */
const processRequest = function(peripheral, request, debug) {
    return new Promise(function(resolve, reject) {
        if (peripheral) {
            if (debug) console.log('Attempting to connect to the HSM...');
            peripheral.connect(function(cause) {
                if (!cause) {
                    if (debug) console.log('Successfully connected.');
                    peripheral.discoverServices([UART_SERVICE_ID], function(cause, services) {
                        if (!cause && services.length === 1) {
                            services[0].discoverCharacteristics([], async function(cause, characteristics) {
                                if (!cause) {
                                    var input, output;
                                    characteristics.forEach (characteristic => {
                                        // TODO: make it more robust by checking properties instead of Ids
                                        if (characteristic.uuid === UART_NOTIFICATION_ID) input = characteristic;
                                        if (characteristic.uuid === UART_WRITE_ID) output = characteristic;
                                    });
                                    if (input && output) {
                                        if (debug) console.log('Sending the request to the HSM...');
                                        // process any extra blocks in reverse order
                                        var buffer, offset, blockSize;
                                        var extraBlocks = Math.ceil((request.length - 2) / BLOCK_SIZE) - 1;
                                        var block = extraBlocks;
                                        while (block > 0) {
                                            // the offset includes the header bytes
                                            offset = block * BLOCK_SIZE + 2;
                                    
                                            // calculate the current block size
                                            blockSize = Math.min(request.length - offset, BLOCK_SIZE);
                                    
                                            // copy the request block into the buffer
                                            buffer = request.slice(offset, offset + blockSize);
                                    
                                            // prepend the header to the buffer
                                            buffer = Buffer.concat([Buffer.from([0x00, block & 0xFF]), buffer], blockSize + 2);
                                    
                                            // process the extended request buffer
                                            try {
                                                await processBlock(input, output, buffer, debug);
                                            } catch (cause) {
                                                reject(cause);
                                            }

                                            block--;
                                        }
                                    
                                        // process the actual request
                                        blockSize = Math.min(request.length, BLOCK_SIZE + 2);
                                        buffer = request.slice(0, blockSize);
                                        try {
                                            const response = await processBlock(input, output, buffer, debug);
                                            if (debug) console.log('A response was received from the HSM.');
                                            peripheral.disconnect(function() {
                                                if (debug) console.log('Disconnected from the HSM.');
                                                resolve(response);
                                            });
                                        } catch (cause) {
                                            reject(cause);
                                        }
                                    } else {
                                        peripheral.disconnect(function() {
                                            if (debug) console.log('Disconnected from the HSM.');
                                            reject("The UART service doesn't support the right characteristics.");
                                        });
                                    }
                                } else {
                                    peripheral.disconnect(function() {
                                        if (debug) console.log('Disconnected from the HSM.');
                                        reject(cause);
                                    });
                                }
                            });
                        } else {
                            cause = cause || Error('Wrong number of UART services found.');
                            peripheral.disconnect(function() {
                                if (debug) console.log('Disconnected from the HSM.');
                                reject(cause);
                            });
                        }
                    });
                } else {
                    peripheral.disconnect(function() {
                        if (debug) console.log('Disconnected from the HSM.');
                        reject(cause);
                    });
                }
            });
        } else {
            reject('No HSM is near by.');
        }
    });
};
