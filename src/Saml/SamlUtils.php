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
     * Parse saml response.
     *
     * @param  array    $payload
     * @return Response
     */
    public function parseSamlResponse(array $payload)
    {
        $deserialization_context = new DeserializationContext();
        $deserialization_context->getDocument()->loadXML(base64_decode($payload['SAMLResponse']));

        $saml_response = new Response();
        $saml_response->deserialize($deserialization_context->getDocument()->firstChild, $deserialization_context);

        return $saml_response;
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
