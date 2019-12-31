<?php

/*
 * This file is part of the Active Collab Authentication project.
 *
 * (c) A51 doo <info@activecollab.com>. All rights reserved.
 */

declare(strict_types=1);

namespace ActiveCollab\Authentication\AuthenticationResult\Transport;

use ActiveCollab\Authentication\Adapter\AdapterInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class Transport implements TransportInterface
{
    private $adapter;
    private $payload;

    public function __construct(AdapterInterface $adapter, $payload = null)
    {
        $this->adapter = $adapter;
        $this->payload = $payload;
    }

    public function getAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function setPayload($value): TransportInterface
    {
        $this->payload = $value;

        return $this;
    }

    public function isEmpty(): bool
    {
        return false;
    }

    private $is_applied_to_request = false;
    private $is_applied_to_response = false;

    public function applyToRequest(ServerRequestInterface $request): ServerRequestInterface
    {
        if ($this->isEmpty()) {
            throw new LogicException('Empty authentication transport cannot be applied');
        }

        if ($this->is_applied_to_request) {
            throw new LogicException('Authentication transport already applied');
        }

        $this->is_applied_to_request = true;
        return $this->getAdapter()->applyToRequest($request, $this);
    }

    public function applyToResponse(ResponseInterface $response): ResponseInterface
    {
        if ($this->isEmpty()) {
            throw new LogicException('Empty authentication transport cannot be applied');
        }

        if ($this->is_applied_to_response) {
            throw new LogicException('Authentication transport already applied');
        }

        $this->is_applied_to_response = true;
        return $this->getAdapter()->applyToResponse($response, $this);
    }

    public function applyTo(ServerRequestInterface $request, ResponseInterface $response): array
    {
        return [
            $this->applyToRequest($request),
            $this->applyToResponse($response),
        ];
    }

    public function isApplied(): bool
    {
        return $this->is_applied_to_request && $this->is_applied_to_response;
    }

    public function isAppliedToRequest(): bool
    {
        return $this->is_applied_to_request;
    }

    public function isAppliedToResponse(): bool
    {
        return $this->is_applied_to_response;
    }
}
