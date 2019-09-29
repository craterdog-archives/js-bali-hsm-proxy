/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const debug = 0;
const crypto = require('crypto');
const bali = require('bali-component-framework').api(debug);
const account = bali.tag();
const directory = 'test/config/';
const proxy = require('./').proxy(directory, debug);
const notary = require('bali-digital-notary').notary(proxy, account, directory, debug);

exports.cli = function() {
    return {

        transaction: bali.catalog({
            $timestamp: bali.moment(),
            $consumer: bali.text('Derk Norton'),
            $account: account,
            $merchant: bali.reference('https://www.starbucks.com/'),
            $amount: 4.95
        }, {
            $type: '/acme/types/Transaction/v1',
            $tag: bali.tag(),
            $version: bali.version(),
            $permissions: '/bali/permissions/public/v1',
            $previous: bali.pattern.NONE
        }),

        certificate: undefined,
        citation: undefined,
        document: undefined,

        getProtocols: function() {
            const protocols = notary.getProtocols();
            console.log('The protocols include: ' + protocols);
        },

        getCitation: function() {
            notary.getCitation().then(function(citation) {
                console.log('The certificate citation is: ' + citation);
            }).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        },

        forgetKey: function() {
            notary.forgetKey().then(function() {
                console.log('The key was forgotten.');
                this.certificate = undefined;
                this.citation = undefined;
                this.document = undefined;
            }.bind(this)).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        },

        generateKey: function() {
            notary.generateKey().then(function(publicKey) {
                notary.notarizeDocument(publicKey).then(function(certificate) {
                    console.log('The notary certificate is: ' + certificate);
                    this.certificate = certificate;
                    notary.activateKey(certificate).then(function(citation) {
                        console.log('The certificate citation is: ' + citation);
                        this.citation = citation;
                    }.bind(this)).catch(function(exception) {
                        console.error('Received the following exception: ' + exception);
                    });
                }.bind(this)).catch(function(exception) {
                    console.error('Received the following exception: ' + exception);
                });
            }.bind(this)).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        },

        refreshKey: function() {
            notary.refreshKey().then(function(certificate) {
                console.log('The new notarized certificate is: ' + certificate);
                this.certificate = certificate;
                notary.citeDocument(certificate).then(function(citation) {
                    console.log('The new certificate citation is: ' + citation);
                    this.citation = citation;
                }.bind(this)).catch(function(exception) {
                    console.error('Received the following exception: ' + exception);
                });
            }.bind(this)).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        },

        notarizeDocument: function(catalog) {
            notary.notarizeDocument(catalog).then(function(document) {
                console.log('The notarized document is: ' + document);
                this.document = document;
            }.bind(this)).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        },

        validDocument: function(document) {
            const certificate = this.certificate.getValue('$component');
            notary.validDocument(document, certificate).then(function(isValid) {
                console.log('The document is ' + (isValid ? '' : 'not ') + 'valid');
            }).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        },

        citeDocument: function(document) {
            const certificate = this.certificate.getValue('$component');
            notary.citeDocument(document).then(function(citation) {
                console.log('The document citation is: ' + citation);
                this.citation = citation;
            }.bind(this)).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        },

        citationMatches: function(citation, document) {
            notary.citationMatches(citation, document).then(function(matches) {
                console.log('The citation ' + (matches ? 'matches.' : 'does not match.'));
            }).catch(function(exception) {
                console.error('Received the following exception: ' + exception);
            });
        }
    };
};

