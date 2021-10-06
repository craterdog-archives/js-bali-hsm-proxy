/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const debug = 0;  // debug level [0..3]
const crypto = require('crypto');
const mocha = require('mocha');
const chai = require('chai');
const expect = chai.expect;
const assert = require('assert');
const bali = require('bali-component-framework').api();
const account = bali.tag();
const directory = 'test/config/';
const proxy = require('../').proxy(directory, debug);
const notary = require('bali-digital-notary').notary(proxy, account, directory, debug);

// NOTE: this function must be called using 'await'
const sleep = function(ms){
    return new Promise(resolve=>{
        setTimeout(resolve,ms);
    });
};

describe('Bali Nebula™ HSM Proxy', function() {

    var certificate;
    var citation;
    const document = bali.instance('/nebula/examples/Content/v1',{
        $foo: 'bar'
    });
    const style = 'https://bali-nebula.net/static/styles/BDN.css';

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notary.forgetKey();
            await assert.rejects(async function() {
                await notary.notarizeDocument(document);
            });
        });

    });

    describe('Test Key Generation', function() {

        it('should return the correct account tag', function() {
            expect(bali.areEqual(notary.getAccount(), account)).to.equal(true);
        });

        it('should return the protocols', function() {
            const protocols = notary.getProtocols();
            expect(protocols).to.exist;
        });

        it('should generate the keys', async function() {
            const publicKey = await notary.generateKey();
            certificate = await notary.notarizeDocument(publicKey);
            citation = await notary.activateKey(certificate);
            expect(certificate).to.exist;
        });

        it('should retrieve the certificate citation', async function() {
            citation = await notary.getCitation();
            expect(citation).to.exist;
        });

    });

    describe('Test Certificate Validation', function() {

        it('should validate the certificate', async function() {
            expect(certificate.getAttribute('$protocol').toString()).to.equal('v2');
            var isValid = await notary.validContract(certificate, certificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', async function() {
            var isValid = await notary.citationMatches(citation, certificate.getAttribute('$document'));
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Credential Generation and Verification', function() {
        var credentials;

        it('should generate new credentials properly', async function() {
            const salt = bali.tag();
            credentials = await notary.generateCredentials(salt);
            expect(credentials).to.exist;
        });

        it('should validate the credentials properly', async function() {
            const isValid = await notary.validContract(credentials, certificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Citations', function() {
        var contract, citation;
        const tag = bali.tag();
        const previous = bali.catalog({
            $protocol: 'v1',
            $tag: tag,
            $version: 'v2.3',
            $digest: "'JB2NG73VTB957T9TZWT44KRZVQ467KWJ2MSJYT6YW2RQAYQMSR861XGM5ZCDCPNJYR612SJT9RFKHA9YZ5DJMLYC7N3127AY4QDVJ38'"
        }, {
            $type: '/nebula/notary/Citation/v1'
        });
        const transaction = bali.catalog({
            $transactionId: bali.tag(),
            $timestamp: bali.moment(),
            $consumer: '"Derk Norton"',
            $merchant: '<https://www.starbucks.com/>',
            $amount: 4.95
        }, {
            $type: '/acme/types/Transaction/v2.3',
            $tag: tag,
            $version: 'v2.4',
            $permissions: '/nebula/permissions/public/v1',
            $previous: previous
        });

        it('should cite a document properly', async function() {
            citation = await notary.citeDocument(transaction);
            expect(citation).to.exist;
        });

        it('should validate the citation properly', async function() {
            var matches = await notary.citationMatches(citation, transaction);
            expect(matches).to.equal(true);
        });

        it('should notarize a document properly', async function() {
            contract = await notary.notarizeDocument(transaction);
        });

        it('should validate the contract properly', async function() {
            var isValid = await notary.validContract(contract, certificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Key Rotation', function() {

        it('should refresh a notary key properly', async function() {
            var newCertificate = await notary.refreshKey();
            expect(newCertificate).to.exist;

            var isValid = await notary.validContract(newCertificate, certificate);
            expect(isValid).to.equal(true);

            const contract = await notary.notarizeDocument(document);

            isValid = await notary.validContract(contract, certificate);
            expect(isValid).to.equal(false);

            isValid = await notary.validContract(contract, newCertificate);
            expect(isValid).to.equal(true);

            certificate = newCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a document twice properly', async function() {
            var contract = await notary.notarizeDocument(document);

            var isValid = await notary.validContract(contract, certificate);
            expect(isValid).to.equal(true);

            const copy = bali.duplicate(document);
            copy.setParameter('$tag', document.getParameter('$tag')),
            copy.setParameter('$version', 'v2');
            copy.setParameter('$permissions', '/nebula/permissions/public/v1');
            copy.setParameter('$previous', 'none');
            contract = await notary.notarizeDocument(copy);

            isValid = await notary.validContract(contract, certificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notary.forgetKey();
            await assert.rejects(async function() {
                await notary.notarizeDocument(document);
            });
        });

    });

});
