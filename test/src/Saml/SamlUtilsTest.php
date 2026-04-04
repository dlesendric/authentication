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
use LightSaml\Model\Protocol\Response;

class SamlUtilsTest extends TestCase
{
    private SamlUtils $saml_utils;
    private array $raw_saml_response;

    public function setUp(): void
    {
        parent::setUp();

        $this->saml_utils = new SamlUtils();
        $this->raw_saml_response = [
            'SAMLResponse' => 'PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6UmVzcG9uc2UgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgSUQ9Il9iMTkxMGJiMDM2OTQ0ODAzYTVkZTA5ZTU0OWYwNzJiYWIyMDg3Yjk1Y2YiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDE2LTExLTE1VDA5OjU1OjA1WiIgRGVzdGluYXRpb249Imh0dHA6Ly9sb2NhbGhvc3Q6ODg4Ny9hcGkvdjEvdXNlci1zZXNzaW9uIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL2xvY2FsaG9zdDo4ODg3L3Byb2plY3RzPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjX2IxOTEwYmIwMzY5NDQ4MDNhNWRlMDllNTQ5ZjA3MmJhYjIwODdiOTVjZiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+NERoS1BwbHRLQ1ZYcjRmNjhQZmxoOE8vTTlzPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5SZU9qL2xFemlBc3dKUWNmQ1RBYzJxYm5aS1MrT2FZUFcydWh1UW9hZVgzbjFibXBRZWcySnlOd0dHcWlHd0lZN0JwU3poMEFEeGhwZlJYSjEwZ2xNQmhNZlVmcnBTN3hMYm82VThpS1A4ZjBDUUJtd0Z2WVhpU2RrRVg1bGIyRkY0bkY0b1M4dVJWVkcrUGpjL0hWYkJOcnQxaDg0bHRTYTdwMnZmSDdua1hkRmI3ZEhQOFFFSUUxY0UzbG0xeU8wbkZLa25KbHNVd0JELzFGbVFDRkFQcEk4cFpaVElibi9ITWlPeUE5VlU0Q1dtNzA0WHlzT2crRkJDZFN6REJzbHNWTktUL01HaCs1bTNnQmhsREl6ZnkvTHZnNGl3YkVZVzdPeWxxZjUxYi9uODU4ekNremM5WVp0MEpvUlZsS1Nkc2cwOVFNcUJWWGFvaG1kYWhpZmc9PTwvZHM6U2lnbmF0dXJlVmFsdWU+DQo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlEeWpDQ0FyS2dBd0lCQWdJSkFKTk9GdVFkNzI3Y01BMEdDU3FHU0liM0RRRUJCUVVBTUV3eEN6QUpCZ05WQkFZVEFsSlRNUkV3RHdZRFZRUUlFd2hDWld4bmNtRmtaVEVTTUJBR0ExVUVDaE1KVEdsbmFIUlRRVTFNTVJZd0ZBWURWUVFERXcxc2FXZG9kSE5oYld3dVkyOXRNQjRYRFRFMU1Ea3hNekU1TURFME1Gb1hEVEkxTURreE1ERTVNREUwTUZvd1RERUxNQWtHQTFVRUJoTUNVbE14RVRBUEJnTlZCQWdUQ0VKbGJHZHlZV1JsTVJJd0VBWURWUVFLRXdsTWFXZG9kRk5CVFV3eEZqQVVCZ05WQkFNVERXeHBaMmgwYzJGdGJDNWpiMjB3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQzdwVUtPUE15RTJvU2NITFBHSkZUZXBLOWoxSDAzZS9zL1duT053OFp3WUJhQklZSVF1WDZ1RThqRlBkRDB1UVNhWXBPdzVoNVRncTZ4QlY3bTJrUE81M2hzOGdFR1dSYkNkQ3R4aTlFTUp3SU9Zcitpc0cwTitEdlY5S3liSmY2dHFjTTUwUGlGalZOdGZ4OEl1Yk1wQUtDYnF1YXFkTGFISDByZ1AxaGJnbkdtNVlaa3lFSzRzOHh1TFVEUzZxTDdON2EvZXoyWms0NXUzTDNxRmN1bmNQSTVCVG5KZzZmcWx5cERoQ0RPQkk1TGp3MTBIbWdaSFBJWHpPaEVQVlYrclgyaUhoRjRWOXZ6RW9lSVVBQllYUVZOUlJOSHBQZFZzSzZpVFRreXZickdKL3R2M29GWmhOT1NMMEt1eStROW5sRTlmRUZxeVV5ZEo2N3ZzWHFaQWdNQkFBR2pnYTR3Z2Fzd0hRWURWUjBPQkJZRUZIUFQ2RXkxcWd4TXpNSXQyZDNPV3V3emZQU1VNSHdHQTFVZEl3UjFNSE9BRkhQVDZFeTFxZ3hNek1JdDJkM09XdXd6ZlBTVW9WQ2tUakJNTVFzd0NRWURWUVFHRXdKU1V6RVJNQThHQTFVRUNCTUlRbVZzWjNKaFpHVXhFakFRQmdOVkJBb1RDVXhwWjJoMFUwRk5UREVXTUJRR0ExVUVBeE1OYkdsbmFIUnpZVzFzTG1OdmJZSUpBSk5PRnVRZDcyN2NNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUZCUUFEZ2dFQkFIa0h0d0pCb2VPaHZyMDZNME1pa0tjOTl6ZTZUcUFHdmYrUWtnRm9WMXNXR0FoM05LY0FSK1hTbGZLK3NRV3JIR2tpaWE1aFdLZ0FQTU1VYmtMUDlERldramJLMjQxaXNDWlpEL0x2QTFhbmJWKzdQaWRuK3N3WjVkUjd5blgydmowa0ZZYitWc0dQa2F2TmNqOFJOL0RkdWhOL1RtaTVzUUFsV2hhdzA2VUFlRXFYdEZlTGJUZ0xmZkJhajdQbVIwSVlqdlRaQTBYMkZkUnUwR1hSeG43emdoanB2U3E5bnVXYTNwR2JmZFZ0TDZHSWt3WVVQY0R6anI0T2VHWE5tSVplL3dNQ256NlZHWlkrTFVnemkvNERBQzZWM09qTXVoZHFTLzIrbzErQ1hDd04wOENJSFFWNitBVUJlbkVWYXdNc2lhZExCZ3gza0ZlNWlYcllSTUE9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PEFzc2VydGlvbiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9Il9jZWI4NjIwODc4MTg2NjVmMDM5MzdkMzE4MGU3OGJkY2UzZWNhMDBhZDQiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDE2LTExLTE1VDA5OjU1OjA1WiI+PElzc3Vlcj5odHRwOi8vbG9jYWxob3N0Ojg4ODcvcHJvamVjdHM8L0lzc3Vlcj48U3ViamVjdD48TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj5vd25lckBjb21wYW55LmNvbTwvTmFtZUlEPjxTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PFN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iaWRfb2ZfdGhlX2F1dGhuX3JlcXVlc3QiIE5vdE9uT3JBZnRlcj0iMjAxNi0xMS0xNVQwOTo1NjowNVoiIFJlY2lwaWVudD0iaHR0cDovL2xvY2FsaG9zdDo4ODg3L2FwaS92MS91c2VyLXNlc3Npb24iLz48L1N1YmplY3RDb25maXJtYXRpb24+PC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0xMS0xNVQwOTo1NTowNVoiIE5vdE9uT3JBZnRlcj0iMjAxNi0xMS0xNVQwOTo1NjowNVoiPjxBdWRpZW5jZVJlc3RyaWN0aW9uPjxBdWRpZW5jZT5odHRwOi8vbG9jYWxob3N0Ojg4ODcvYXBpL3YxL3VzZXItc2Vzc2lvbjwvQXVkaWVuY2U+PC9BdWRpZW5jZVJlc3RyaWN0aW9uPjwvQ29uZGl0aW9ucz48QXR0cmlidXRlU3RhdGVtZW50PjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZW1haWxhZGRyZXNzIj48QXR0cmlidXRlVmFsdWU+b3duZXJAY29tcGFueS5jb208L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0ic2Vzc2lvbl9kdXJhdGlvbl90eXBlIj48QXR0cmlidXRlVmFsdWU+bG9uZzwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PC9BdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0xMS0xNVQwOTo0NTowNVoiIFNlc3Npb25JbmRleD0iX3NvbWVfc2Vzc2lvbl9pbmRleCI+PEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8L0F1dGhuQ29udGV4dENsYXNzUmVmPjwvQXV0aG5Db250ZXh0PjwvQXV0aG5TdGF0ZW1lbnQ+PC9Bc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4NCg==',
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
        $parsed_response = $this->saml_utils->parseSamlResponse($this->raw_saml_response);

        $this->assertInstanceOf(Response::class, $parsed_response);
    }

    public function testEmailAddress()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse($this->raw_saml_response);

        $email = $this->saml_utils->getEmailAddress($parsed_response);

        $this->assertSame('owner@company.com', $email);
    }

    public function testSessionDuration()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse($this->raw_saml_response);

        $session_duration_type = $this->saml_utils->getSessionDurationType($parsed_response);

        $this->assertSame(SessionInterface::SESSION_DURATION_LONG, $session_duration_type);
    }

    public function testIssuerUrl()
    {
        $parsed_response = $this->saml_utils->parseSamlResponse($this->raw_saml_response);

        $url = $this->saml_utils->getIssuerUrl($parsed_response);

        $this->assertSame('http://localhost:8887/projects', $url);
    }
}
