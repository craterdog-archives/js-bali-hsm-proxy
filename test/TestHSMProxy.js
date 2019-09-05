/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const debug = false;  // set to true for exception logging
const crypto = require('crypto');
const mocha = require('mocha');
const assert = require('chai').assert;
const expect = require('chai').expect;
const bali = require('bali-component-framework');
const accountTag = bali.tag();
const directory = 'test/config/';
const hsm = require('../').api(debug);
const notaryAPI = require('bali-digital-notary').api(hsm, accountTag, directory, debug);


describe('Bali Nebula™ HSM Proxy', function() {

    var notaryCertificate;
    var certificateCitation;
    var component = bali.parse('[$foo: "bar"]($tag: #MFPCRNKS2SG20CD7VQ6KD329X7382KJY, $version: v1, $permissions: /bali/permissions/public/v1, $previous: none)');

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notaryAPI.forgetKey();
        });

    });

    describe('Test Key Generation', function() {

        it('should return the correct account tag', function() {
            expect(notaryAPI.getAccountTag().isEqualTo(accountTag)).to.equal(true);
        });

        it('should return the protocols', async function() {
            const protocols = await notaryAPI.getProtocols();
            expect(protocols).to.exist;
        });

        it('should generate the keys', async function() {
            const catalog = await notaryAPI.generateKey();
            expect(catalog).to.exist;
            notaryCertificate = await notaryAPI.notarizeDocument(catalog);
            expect(notaryCertificate).to.exist;
            certificateCitation = await notaryAPI.activateKey(notaryCertificate);
        });

        it('should retrieve the certificate citation', async function() {
            const expected = await notaryAPI.getCitation();
            expect(expected).to.exist;
            expect(certificateCitation.isEqualTo(expected)).to.equal(true);
        });

    });

    describe('Test Certificate Validation', function() {

        it('should validate the certificate', async function() {
            expect(notaryCertificate.getValue('$protocol').toString()).to.equal('v1');
            const certificate = notaryCertificate.getValue('$component');
            var isValid = await notaryAPI.documentValid(notaryCertificate, certificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', async function() {
            var isValid = await notaryAPI.citationMatches(certificateCitation, notaryCertificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', async function() {
            const tag = bali.tag();
            const previous = bali.catalog({
                $protocol: bali.version(),
                $timestamp: bali.parse('<2019-02-24T22:41:18.843>'),
                $tag: tag,
                $version: bali.version([2, 3]),
                $digest: bali.parse("'JB2NG73VTB957T9TZWT44KRZVQ467KWJ2MSJYT6YW2RQAYQMSR861XGM5ZCDCPNJYR612SJT9RFKHA9YZ5DJMLYC7N3127AY4QDVJ38'")
            }, bali.parameters({
                $type: bali.parse('/bali/notary/Citation/v1')
            }));
            const transaction = bali.catalog({
                $transactionId: bali.tag(),
                $timestamp: bali.moment(),
                $consumer: bali.text('Derk Norton'),
                $merchant: bali.reference('https://www.starbucks.com/'),
                $amount: 4.95
            }, bali.parameters({
                $type: bali.parse('/acme/types/Transaction/v2.3'),
                $tag: tag,
                $version: bali.version([2, 4]),
                $permissions: bali.parse('/bali/permissions/public/v1'),
                $previous: previous
            }));
            var document = await notaryAPI.notarizeDocument(transaction);

            const certificate = notaryCertificate.getValue('$component');

            var citation = await notaryAPI.citeDocument(document);
            var isValid = await notaryAPI.documentValid(document, certificate);
            expect(isValid).to.equal(true);
            var matches = await notaryAPI.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Key Rotation', function() {

        it('should rotate a notary key properly', async function() {
            var newNotaryCertificate = await notaryAPI.rotateKey();
            expect(newNotaryCertificate).to.exist;

            const certificate = notaryCertificate.getValue('$component');
            const newCertificate = newNotaryCertificate.getValue('$component');

            var isValid = await notaryAPI.documentValid(newNotaryCertificate, certificate);
            expect(isValid).to.equal(true);

            var document = await notaryAPI.notarizeDocument(component);

            var citation = await notaryAPI.citeDocument(document);
            isValid = await notaryAPI.documentValid(document, certificate);
            expect(isValid).to.equal(false);

            isValid = await notaryAPI.documentValid(document, newCertificate);
            expect(isValid).to.equal(true);

            var matches = await notaryAPI.citationMatches(citation, document);
            expect(matches).to.equal(true);

            notaryCertificate = newNotaryCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a component twice properly', async function() {
            var document = await notaryAPI.notarizeDocument(component);

            const certificate = notaryCertificate.getValue('$component');

            var citation = await notaryAPI.citeDocument(document);
            var isValid = await notaryAPI.documentValid(document, certificate);
            expect(isValid).to.equal(true);
            var matches = await notaryAPI.citationMatches(citation, document);
            expect(matches).to.equal(true);

            document = bali.duplicate(document);
            const parameters = document.getParameters();
            parameters.setParameter('$tag', document.getValue('$component').getParameters().getParameter('$tag'));
            parameters.setParameter('$version', 'v2');
            parameters.setParameter('$permissions', bali.parse('/bali/permissions/public/v1'));
            parameters.setParameter('$previous', bali.NONE);
            document = await notaryAPI.notarizeDocument(document);

            citation = await notaryAPI.citeDocument(document);
            isValid = await notaryAPI.documentValid(document, certificate);
            expect(isValid).to.equal(true);
            matches = await notaryAPI.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notaryAPI.forgetKey();
            try {
                await notaryAPI.notarizeDocument(component);
                assert.fail('The attempt to sign a component without a key should have failed.');
            } catch (error) {
                // expected
            };
        });

    });

});
