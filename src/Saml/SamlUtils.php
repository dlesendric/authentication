<?php

/*
 * This file is part of the Active Collab Authentication project.
 *
 * (c) A51 doo <info@activecollab.com>. All rights reserved.
 */

declare(strict_types=1);

namespace ActiveCollab\Authentication\Saml;

use ActiveCollab\Authentication\Session\SessionInterface;
use DateTime;
use InvalidArgumentException;
use LightSaml\Binding\BindingFactory;
use LightSaml\ClaimTypes;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Context\DeserializationContext;
use LightSaml\Model\Context\SerializationContext;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\SamlConstants;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Symfony\Component\HttpFoundation\RedirectResponse;

class SamlUtils
{
    const SESSION_DURATION_TYPE_ATTRIBUTE_NAME = 'session_duration_type';

    /**
     * Get saml authnRequest.
     *
     * @param  string $consumer_service_url
     * @param  string $idp_destination
     * @param  string $issuer
     * @param  string $saml_crt
     * @param  string $saml_key
     * @return string
     */
    public function getAuthnRequest(
        $consumer_service_url,
        $idp_destination,
        $issuer,
        $saml_crt,
        $saml_key
    ) {
        $authn_request = new AuthnRequest();
        $authn_request
            ->setAssertionConsumerServiceURL($consumer_service_url)
            ->setProtocolBinding(SamlConstants::BINDING_SAML2_HTTP_POST)
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($idp_destination)
            ->setIssuer(new Issuer($issuer));

        $certificate = new X509Certificate();
        $certificate->loadPem($saml_crt);
        $private_key = KeyHelper::createPrivateKey($saml_key, '', false, XMLSecurityKey::RSA_SHA256);

        $authn_request->setSignature(new SignatureWriter($certificate, $private_key, XMLSecurityDSig::SHA256));

        $serialization_context = new SerializationContext();
        $authn_request->serialize($serialization_context->getDocument(), $serialization_context);

        $binding_factory = new BindingFactory();
        $redirect_binding = $binding_factory->create(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);

        $message_context = new MessageContext();
        $message_context->setMessage($authn_request);

        /** @var RedirectResponse $http_response */
        $http_response = $redirect_binding->send($message_context);

        return $http_response->getTargetUrl();
    }

    /**
     * Parse saml response and validate its signature against the trusted IDP certificate.
     *
     * @param  array    $payload
     * @param  string   $idp_certificate PEM-encoded public certificate of the trusted IDP
     * @return Response
     */
    public function parseSamlResponse(array $payload, string $idp_certificate): Response
    {
        $deserialization_context = new DeserializationContext();
        $deserialization_context->getDocument()->loadXML(base64_decode($payload['SAMLResponse']));

        $saml_response = new Response();
        $saml_response->deserialize($deserialization_context->getDocument()->firstChild, $deserialization_context);

        $this->validateSignature($saml_response, $idp_certificate);

        return $saml_response;
    }

    private function validateSignature(Response $saml_response, string $idp_certificate): void
    {
        if (empty($idp_certificate)) {
            throw new InvalidArgumentException('IDP certificate is required for SAML signature validation');
        }

        $certificate = new X509Certificate();
        $certificate->loadPem($idp_certificate);
        $key = KeyHelper::createPublicKey($certificate);

        $signed = false;

        $response_signature = $saml_response->getSignature();
        if ($response_signature !== null) {
            $response_signature->validate($key);
            $signed = true;
        }

        foreach ($saml_response->getAllAssertions() as $assertion) {
            $assertion_signature = $assertion->getSignature();
            if ($assertion_signature !== null) {
                $assertion_signature->validate($key);
                $signed = true;
            }
        }

        if (!$signed) {
            throw new InvalidArgumentException('SAML response contains no signature');
        }
    }

    /**
     * @param  Response    $response
     * @return null|string
     */
    public function getEmailAddress(Response $response)
    {
        foreach ($response->getAllAssertions() as $assertion) {
            foreach ($assertion->getAllAttributeStatements() as $statement) {
                $username = $statement->getFirstAttributeByName(ClaimTypes::EMAIL_ADDRESS);

                if ($username) {
                    return $username->getFirstAttributeValue();
                }
            }
        }

        return null;
    }

    public function getSessionDurationType(Response $response)
    {
        foreach ($response->getAllAssertions() as $assertion) {
            foreach ($assertion->getAllAttributeStatements() as $statement) {
                $session_type = $statement->getFirstAttributeByName(SsoResponse::SESSION_DURATION_TYPE_ATTRIBUTE_NAME);

                if ($session_type && $this->validateSessionType($session_type->getFirstAttributeValue())) {
                    return $session_type->getFirstAttributeValue();
                }
            }
        }

        return SessionInterface::DEFAULT_SESSION_DURATION;
    }

    /**
     * @param  Response $response
     * @return string
     */
    public function getIssuerUrl(Response $response)
    {
        return $response->getIssuer()->getValue();
    }

    private function validateSessionType($session_type)
    {
        if (!in_array($session_type, SessionInterface::SESSION_DURATIONS)) {
            throw new InvalidArgumentException('Invalid session duration value');
        }

        return true;
    }
}
