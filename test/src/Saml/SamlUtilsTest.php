<?php

/*
 * This file is part of the Active Collab Authentication project.
 *
 * (c) A51 doo <info@activecollab.com>. All rights reserved.
 */

namespace ActiveCollab\Authentication\Test\Saml;

use ActiveCollab\Authentication\Saml\SamlUtils;
use ActiveCollab\Authentication\Session\SessionInterface;
use ActiveCollab\Authentication\Test\TestCase\TestCase;
use LightSaml\ClaimTypes;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Error\LightSamlSecurityException;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Assertion\Subject;
use LightSaml\Model\Context\SerializationContext;
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\SamlConstants;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SamlUtilsTest extends TestCase
{
    private SamlUtils $saml_utils;
    private string $idp_certificate;
    private string $idp_private_key;
    private array $signed_saml_response;
    private array $unsigned_saml_response;

    public function setUp(): void
    {
        parent::setUp();

        $this->saml_utils = new SamlUtils();

        [$this->idp_certificate, $this->idp_private_key] = $this->generateKeyPair();

        $this->signed_saml_response = [
            'SAMLResponse' => $this->createSignedSamlResponse(
                'owner@company.com',
                SessionInterface::SESSION_DURATION_LONG,
                'http://localhost:8887/projects',
                $this->idp_certificate,
                $this->idp_private_key
            ),
        ];

        $this->unsigned_saml_response = [
            'SAMLResponse' => base64_encode(
                '<?xml version="1.0"?>'
                . '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_nosig" Version="2.0" IssueInstant="2016-11-15T09:55:05Z">'
                . '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://localhost:8887/projects</saml:Issuer>'
                . '<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" Version="2.0" IssueInstant="2016-11-15T09:55:05Z">'
                . '<Issuer>http://localhost:8887/projects</Issuer>'
                . '</Assertion>'
                . '</samlp:Response>'
            ),
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

    public function testParseSamlResponse()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse($this->signed_saml_response, $this->idp_certificate);

        $this->assertInstanceOf(Response::class, $parsed_response);
    }

    public function testParseSamlResponseThrowsOnInvalidSignature()
    {
        $this->expectException(LightSamlSecurityException::class);

        [$wrong_certificate] = $this->generateKeyPair();
        $this->saml_utils->parseSamlResponse($this->signed_saml_response, $wrong_certificate);
    }

    public function testParseSamlResponseThrowsOnMissingSignature()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('SAML response contains no signature');

        $this->saml_utils->parseSamlResponse($this->unsigned_saml_response, $this->idp_certificate);
    }

    public function testParseSamlResponseThrowsOnEmptyCertificate()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('IDP certificate is required for SAML signature validation');

        $this->saml_utils->parseSamlResponse($this->signed_saml_response, '');
    }

    public function testEmailAddress()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse($this->signed_saml_response, $this->idp_certificate);

        $this->assertSame('owner@company.com', $this->saml_utils->getEmailAddress($parsed_response));
    }

    public function testSessionDuration()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse($this->signed_saml_response, $this->idp_certificate);

        $this->assertSame(
            SessionInterface::SESSION_DURATION_LONG,
            $this->saml_utils->getSessionDurationType($parsed_response)
        );
    }

    public function testIssuerUrl()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse($this->signed_saml_response, $this->idp_certificate);

        $this->assertSame('http://localhost:8887/projects', $this->saml_utils->getIssuerUrl($parsed_response));
    }

    private function generateKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => 'test-idp'], $key);
        $x509 = openssl_csr_sign($csr, null, $key, 365);

        openssl_x509_export($x509, $cert_pem);
        openssl_pkey_export($key, $key_pem);

        return [$cert_pem, $key_pem];
    }

    private function createSignedSamlResponse(
        string $email,
        string $session_duration,
        string $issuer_url,
        string $cert_pem,
        string $key_pem
    ): string {
        $certificate = new X509Certificate();
        $certificate->loadPem($cert_pem);
        $private_key = KeyHelper::createPrivateKey($key_pem, '', false, XMLSecurityKey::RSA_SHA256);

        $email_attr = (new Attribute())
            ->setName(ClaimTypes::EMAIL_ADDRESS)
            ->addAttributeValue($email);

        $session_attr = (new Attribute())
            ->setName(SamlUtils::SESSION_DURATION_TYPE_ATTRIBUTE_NAME)
            ->addAttributeValue($session_duration);

        $attr_stmt = (new AttributeStatement())
            ->addAttribute($email_attr)
            ->addAttribute($session_attr);

        $subject = (new Subject())
            ->setNameID((new NameID())->setFormat(SamlConstants::NAME_ID_FORMAT_EMAIL)->setValue($email));

        $assertion = new Assertion();
        $assertion->setIssuer(new Issuer($issuer_url));
        $assertion->setSubject($subject);
        $assertion->addItem($attr_stmt);
        $assertion->setSignature(new SignatureWriter($certificate, $private_key, XMLSecurityDSig::SHA256));

        $response = new Response();
        $response->setIssuer(new Issuer($issuer_url));
        $response->addAssertion($assertion);

        $context = new SerializationContext();
        $response->serialize($context->getDocument(), $context);

        return base64_encode($context->getDocument()->saveXML());
    }
}
