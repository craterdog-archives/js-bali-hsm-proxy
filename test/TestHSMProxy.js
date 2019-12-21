/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const debug = 3;  // debug level [0..3]
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

const sleep = function(ms){
    return new Promise(resolve=>{
        setTimeout(resolve,ms);
    });
};

describe('Bali Nebula™ HSM Proxy', function() {

    var notaryCertificate;
    var certificateCitation;
    var component = bali.component('[$foo: "bar"]($type: /bali/examples/Content/v1, $tag: #MFPCRNKS2SG20CD7VQ6KD329X7382KJY, $version: v1, $permissions: /bali/permissions/public/v1, $previous: none)');

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notary.forgetKey();
        });

    });

    describe('Test Key Generation', function() {

        it('should return the correct account tag', function() {
            expect(notary.getAccount().isEqualTo(account)).to.equal(true);
        });

        it('should return the protocols', function() {
            const protocols = notary.getProtocols();
            expect(protocols).to.exist;
        });

        it('should generate the keys', async function() {
            const catalog = await notary.generateKey();
            expect(catalog).to.exist;
            notaryCertificate = await notary.notarizeDocument(catalog);
            expect(notaryCertificate).to.exist;
            certificateCitation = await notary.activateKey(notaryCertificate);
        });

        it('should retrieve the certificate citation', async function() {
            const expected = await notary.getCitation();
            expect(expected).to.exist;
            expect(certificateCitation.isEqualTo(expected)).to.equal(true);
        });

    });

    describe('Test Certificate Validation', function() {

        it('should validate the certificate', async function() {
            expect(notaryCertificate.getValue('$protocol').toString()).to.equal('v2');
            var isValid = await notary.validDocument(notaryCertificate, notaryCertificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', async function() {
            var isValid = await notary.citationMatches(certificateCitation, notaryCertificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', async function() {
            const tag = bali.tag();
            const previous = bali.catalog({
                $protocol: bali.version(),
                $timestamp: bali.component('<2019-02-24T22:41:18.843>'),
                $tag: tag,
                $version: bali.version([2, 3]),
                $digest: bali.component("'JB2NG73VTB957T9TZWT44KRZVQ467KWJ2MSJYT6YW2RQAYQMSR861XGM5ZCDCPNJYR612SJT9RFKHA9YZ5DJMLYC7N3127AY4QDVJ38'")
            }, {
                $type: bali.component('/bali/notary/Citation/v1')
            });
            const transaction = bali.catalog({
                $transactionId: bali.tag(),
                $timestamp: bali.moment(),
                $consumer: bali.text('Derk Norton'),
                $merchant: bali.reference('https://www.starbucks.com/'),
                $amount: 4.95
            }, {
                $type: bali.component('/acme/types/Transaction/v2.3'),
                $tag: tag,
                $version: bali.version([2, 4]),
                $permissions: bali.component('/bali/permissions/public/v1'),
                $previous: previous
            });
            var document = await notary.notarizeDocument(transaction);

            var citation = await notary.citeDocument(document);
            var isValid = await notary.validDocument(document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Key Rotation', function() {

        it('should rotate a notary key properly', async function() {
            var newNotaryCertificate = await notary.refreshKey();
            expect(newNotaryCertificate).to.exist;

            var isValid = await notary.validDocument(newNotaryCertificate, notaryCertificate);
            expect(isValid).to.equal(true);

            var document = await notary.notarizeDocument(component);
            var citation = await notary.citeDocument(document);

            isValid = await notary.validDocument(document, notaryCertificate);
            expect(isValid).to.equal(false);

            isValid = await notary.validDocument(document, newNotaryCertificate);
            expect(isValid).to.equal(true);

            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);

            notaryCertificate = newNotaryCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a component twice properly', async function() {
            var document = await notary.notarizeDocument(component);

            var citation = await notary.citeDocument(document);
            var isValid = await notary.validDocument(document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);

            const copy = document.duplicate();
            copy.setParameter('$tag', document.getValue('$content').getParameter('$tag')),
            copy.setParameter('$version', bali.component('v2'));
            copy.setParameter('$permissions', bali.component('/bali/permissions/public/v1'));
            copy.setParameter('$previous', bali.pattern.NONE);
            document = await notary.notarizeDocument(copy);

            citation = await notary.citeDocument(document);
            isValid = await notary.validDocument(document, notaryCertificate);
            expect(isValid).to.equal(true);
            matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notary.forgetKey();
            await assert.rejects(async function() {
                await notary.notarizeDocument(component);
            });
        });

    });

});
