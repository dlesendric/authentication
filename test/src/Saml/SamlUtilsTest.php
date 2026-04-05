<?php

/*
 * This file is part of the Active Collab Authentication project.
 *
 * (c) A51 doo <info@activecollab.com>. All rights reserved.
 */

namespace ActiveCollab\Authentication\Test\Saml;

use ActiveCollab\Authentication\Saml\Exception\InvalidSamlResponseException;
use ActiveCollab\Authentication\Saml\Exception\InvalidSamlSignatureException;
use ActiveCollab\Authentication\Saml\SamlUtils;
use ActiveCollab\Authentication\Session\SessionInterface;
use ActiveCollab\Authentication\Test\TestCase\TestCase;
use LightSaml\Model\Protocol\Response;

class SamlUtilsTest extends TestCase
{
    private SamlUtils $saml_utils;
    private array $raw_saml_response;
    private string $idp_certificate;

    public function setUp(): void
    {
        parent::setUp();

        $this->saml_utils = new SamlUtils();
        $this->idp_certificate = file_get_contents(__DIR__ . '/../Fixtures/saml.crt');
        $this->raw_saml_response = [
            'SAMLResponse' => file_get_contents(__DIR__ . '/../Fixtures/saml_sha256.txt'),
        ];
    }

    public function testAuthnRequest()
    {
        $result = $this->saml_utils->getAuthnRequest(
            'http://localhost/consumer',
            'http://localhost/idp',
            'http://localhost/issuer',
            file_get_contents(__DIR__ . '/../Fixtures/saml.crt'),
            file_get_contents(__DIR__ . '/../Fixtures/saml.key')
        );

        $this->assertStringStartsWith('http://localhost/idp?SAMLRequest=', $result);
    }

    public function testAuthnRequestUsesRsaSha256Signature()
    {
        $result = $this->saml_utils->getAuthnRequest(
            'http://localhost/consumer',
            'http://localhost/idp',
            'http://localhost/issuer',
            file_get_contents(__DIR__ . '/../Fixtures/saml.crt'),
            file_get_contents(__DIR__ . '/../Fixtures/saml.key')
        );

        $url_parts = parse_url($result);
        parse_str($url_parts['query'], $query);

        $this->assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', $query['SigAlg']);
    }

    private function getParsedResponse(): Response
    {
        $parsed_response = $this->saml_utils->parseSamlResponse(
            $this->raw_saml_response,
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );

        foreach ($parsed_response->getAllAssertions() as $assertion) {
            $assertion->getConditions()
                ->setNotBefore(time() - 3600)
                ->setNotOnOrAfter(time() + 3600);
        }

        return $parsed_response;
    }

    public function testParseSamlResponse()
    {
        $parsed_response = $this->getParsedResponse();

        $this->assertInstanceOf(Response::class, $parsed_response);
    }

    public function testEmailAddress()
    {
        $parsed_response = $this->getParsedResponse();

        $email = $this->saml_utils->getEmailAddress($parsed_response);

        $this->assertSame('owner@company.com', $email);
    }

    public function testSessionDuration()
    {
        $parsed_response = $this->getParsedResponse();

        $session_duration_type = $this->saml_utils->getSessionDurationType($parsed_response);

        $this->assertSame(SessionInterface::SESSION_DURATION_LONG, $session_duration_type);
    }

    public function testIssuerUrl()
    {
        $parsed_response = $this->getParsedResponse();

        $url = $this->saml_utils->getIssuerUrl($parsed_response);

        $this->assertSame('http://localhost/idp', $url);
    }

    /**
     * @dataProvider securityTestAlgorithmProvider
     */
    public function testTamperedResponseIsRejected(string $fixture_path)
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML signature verification failed');

        $xml = base64_decode(file_get_contents($fixture_path));
        $xml = str_replace('owner@company.com', 'tampered@company.com', $xml);
        $tampered_payload = ['SAMLResponse' => base64_encode($xml)];

        $this->saml_utils->parseSamlResponse(
            $tampered_payload,
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }

    /**
     * @dataProvider securityTestAlgorithmProvider
     */
    public function testMissingSignatureIsRejected(string $fixture_path)
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML response is not signed.');

        $xml = base64_decode(file_get_contents($fixture_path));
        // Remove Signature element.
        $xml = preg_replace('/<ds:Signature.*<\/ds:Signature>/Uis', '', $xml);
        $unsigned_payload = ['SAMLResponse' => base64_encode($xml)];

        $this->saml_utils->parseSamlResponse(
            $unsigned_payload,
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }

    /**
     * @dataProvider securityTestAlgorithmProvider
     */
    public function testWrongCertificateIsRejected(string $fixture_path)
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML signature verification failed');

        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => 'wrong-idp'], $res);
        $x509 = openssl_csr_sign($csr, null, $res, 1);
        openssl_x509_export($x509, $wrong_certificate);

        $this->saml_utils->parseSamlResponse(
            ['SAMLResponse' => file_get_contents($fixture_path)],
            $wrong_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }

    /**
     * @dataProvider securityTestAlgorithmProvider
     */
    public function testExpiredAssertionIsRejected(string $fixture_path)
    {
        $this->expectException(InvalidSamlResponseException::class);
        $this->expectExceptionMessage('SAML assertion has expired.');

        $parsed_response = $this->saml_utils->parseSamlResponse(
            ['SAMLResponse' => file_get_contents($fixture_path)],
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );

        // Manually set an expired condition
        foreach ($parsed_response->getAllAssertions() as $assertion) {
            $assertion->getConditions()->setNotOnOrAfter(time() - 3600);
        }

        $this->saml_utils->validateAssertionConditions(
            $parsed_response,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }

    /**
     * @dataProvider securityTestAlgorithmProvider
     */
    public function testWrongDestinationIsRejected(string $fixture_path)
    {
        $this->expectException(InvalidSamlResponseException::class);
        $this->expectExceptionMessage('SAML response destination mismatch.');

        $this->saml_utils->parseSamlResponse(
            ['SAMLResponse' => file_get_contents($fixture_path)],
            $this->idp_certificate,
            'http://wrong-destination.com',
            'http://localhost:8887/projects'
        );
    }

    /**
     * @dataProvider securityTestAlgorithmProvider
     */
    public function testWrongAudienceIsRejected(string $fixture_path)
    {
        $this->expectException(InvalidSamlResponseException::class);
        $this->expectExceptionMessage('SAML assertion audience mismatch.');

        $this->saml_utils->parseSamlResponse(
            ['SAMLResponse' => file_get_contents($fixture_path)],
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://wrong-audience.com'
        );
    }

    public function testSha1SignatureIsAccepted()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse(
            [
                'SAMLResponse' => file_get_contents(__DIR__ . '/../Fixtures/saml_sha1.txt'),
            ],
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );

        $this->assertInstanceOf(Response::class, $parsed_response);
    }

    public function securityTestAlgorithmProvider(): array
    {
        return [
            'sha256' => [__DIR__ . '/../Fixtures/saml_sha256.txt'],
            'sha1' => [__DIR__ . '/../Fixtures/saml_sha1.txt'],
        ];
    }

    public function testUnsupportedAlgorithmIsRejected()
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML signature algorithm not allowed');

        $xml = base64_decode($this->raw_saml_response['SAMLResponse']);
        $xml = str_replace(
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
            $xml
        );
        $unsupported_payload = ['SAMLResponse' => base64_encode($xml)];

        $this->saml_utils->parseSamlResponse(
            $unsupported_payload,
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }
}
