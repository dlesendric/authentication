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
            'SAMLResponse' => 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iXzlmOGE5MmM4OWZhMTRmN2Y5MjRhMDc5NWIzZTVjNzYwODc4M2JmOGU1OCIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMjYtMDQtMDVUMDY6Mzc6NTRaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo4ODg3L3Byb2plY3RzIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL2xvY2FsaG9zdDo4ODg3L3Byb2plY3RzPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4KICA8ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI185ZjhhOTJjODlmYTE0ZjdmOTI0YTA3OTViM2U1Yzc2MDg3ODNiZjhlNTgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5HRG9aWUkyV3QvOG13V1R1bDgxL3dTSHBOMC9ZenMvTW5mL3NQUnBORE84PTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5nSnFJM1BHbVlJb0wzS2g0cnZjOEpKRm9ZUjl3U01vbzR1Wm9xQXczM04zdFNabDlkcmFzeXNOM202bklGY2JQU3g1cURaT3c1aGRzYWl6RXhLOTBOZVpwTHEwOUExdjUvWU9EamVtTW5lRkU2RS8xUEd5dGw5a3BsTEVZTFB3eC96enZpbWxCN1R5cFBidmtXTDduU2RCelJXclArbUZXbnI2SEprbEQrbVdnTW5seCtsTEE2c2Z4bzdFSkRPZTYvd3NOVWtMQTk1ZlNOMmNSbGExTDJOSXZrNTZuMDVjVnRBSGdBVzA3aHcvSlg5cjVmcnNyTHBQTWZIZG1OYlEyZEF2ZUF2bU1peDdYRkx0UTdjVmxqU1NNeXdnOGZkbXorYWdMd3dhbllqMHUycnpENkM2N2JFL3Y0SjVEYUVacXZHWXNQdjNGaTNUTDNYcE5VRG8waHc9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUR5akNDQXJLZ0F3SUJBZ0lKQUpOT0Z1UWQ3MjdjTUEwR0NTcUdTSWIzRFFFQkJRVUFNRXd4Q3pBSkJnTlZCQVlUQWxKVE1SRXdEd1lEVlFRSUV3aENaV3huY21Ga1pURVNNQkFHQTFVRUNoTUpUR2xuYUhSVFFVMU1NUll3RkFZRFZRUURFdzFzYVdkb2RITmhiV3d1WTI5dE1CNFhEVEUxTURreE16RTVNREUwTUZvWERUSTFNRGt4TURFNU1ERTBNRm93VERFTE1Ba0dBMVVFQmhNQ1VsTXhFVEFQQmdOVkJBZ1RDRUpsYkdkeVlXUmxNUkl3RUFZRFZRUUtFd2xNYVdkb2RGTkJUVXd4RmpBVUJnTlZCQU1URFd4cFoyaDBjMkZ0YkM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDN3BVS09QTXlFMm9TY0hMUEdKRlRlcEs5ajFIMDNlL3MvV25PTnc4WndZQmFCSVlJUXVYNnVFOGpGUGREMHVRU2FZcE93NWg1VGdxNnhCVjdtMmtQTzUzaHM4Z0VHV1JiQ2RDdHhpOUVNSndJT1lyK2lzRzBOK0R2VjlLeWJKZjZ0cWNNNTBQaUZqVk50Zng4SXViTXBBS0NicXVhcWRMYUhIMHJnUDFoYmduR201WVpreUVLNHM4eHVMVURTNnFMN043YS9lejJaazQ1dTNMM3FGY3VuY1BJNUJUbkpnNmZxbHlwRGhDRE9CSTVMancxMEhtZ1pIUElYek9oRVBWVityWDJpSGhGNFY5dnpFb2VJVUFCWVhRVk5SUk5IcFBkVnNLNmlUVGt5dmJyR0ovdHYzb0ZaaE5PU0wwS3V5K1E5bmxFOWZFRnF5VXlkSjY3dnNYcVpBZ01CQUFHamdhNHdnYXN3SFFZRFZSME9CQllFRkhQVDZFeTFxZ3hNek1JdDJkM09XdXd6ZlBTVU1Id0dBMVVkSXdSMU1IT0FGSFBUNkV5MXFneE16TUl0MmQzT1d1d3pmUFNVb1ZDa1RqQk1NUXN3Q1FZRFZRUUdFd0pTVXpFUk1BOEdBMVVFQ0JNSVFtVnNaM0poWkdVeEVqQVFCZ05WQkFvVENVeHBaMmgwVTBGTlRERVdNQlFHQTFVRUF4TU5iR2xuYUhSellXMXNMbU52YllJSkFKTk9GdVFkNzI3Y01Bd0dBMVVkRXdRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQUhrSHR3SkJvZU9odnIwNk0wTWlrS2M5OXplNlRxQUd2ZitRa2dGb1Yxc1dHQWgzTktjQVIrWFNsZksrc1FXckhHa2lpYTVoV0tnQVBNTVVia0xQOURGV2tqYksyNDFpc0NaWkQvTHZBMWFuYlYrN1BpZG4rc3daNWRSN3luWDJ2ajBrRlliK1ZzR1BrYXZOY2o4Uk4vRGR1aE4vVG1pNXNRQWxXaGF3MDZVQWVFcVh0RmVMYlRnTGZmQmFqN1BtUjBJWWp2VFpBMFgyRmRSdTBHWFJ4bjd6Z2hqcHZTcTludVdhM3BHYmZkVnRMNkdJa3dZVVBjRHpqcjRPZUdYTm1JWmUvd01Dbno2VkdaWStMVWd6aS80REFDNlYzT2pNdWhkcVMvMitvMStDWEN3TjA4Q0lIUVY2K0FVQmVuRVZhd01zaWFkTEJneDNrRmU1aVhyWVJNQT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzdkMjU3ZWY4M2ViMjJmZWIyYjQ2NGMyZTkwNjA2ZjY2ZmJhN2M5ZmMzMyIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMjYtMDQtMDVUMDY6Mzc6NTRaIj48SXNzdWVyPmh0dHA6Ly9sb2NhbGhvc3Q6ODg4Ny9wcm9qZWN0czwvSXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogIDxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPgogIDxkczpSZWZlcmVuY2UgVVJJPSIjXzdkMjU3ZWY4M2ViMjJmZWIyYjQ2NGMyZTkwNjA2ZjY2ZmJhN2M5ZmMzMyI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPmFweHZSTGN0dXJVWWwwS3dId1dWK2dvdjVzN0VkeHkzdy9tdUdkdDk0aEE9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPllWcW1XS3B1Qmh1clQwTyswdlR5VHZ1RHpsM2UxWmhnd0Z0eE9URk5abFlER3R0UzhTZ0VtZXplcUtRajM3TU5TMk1rdkhvK3oybWc0WEQxS1lla3pKYWtjV3VvcFUrcFoxZ2FXOGh5NE4yM2RpMGRVMlFVTU14SGJrdlh1QTZJYTJCZTFmN2g5RkJ6K0xCcmpERDBSMXh4NVdYNldibVFBRWJveXRhQ1pTK0tRa1R3QzVxd1VDY3N6ZHFoZ1ZSRU5Za2dpNnRYV0FYR0hGbXVUQS9YcUxvUWxKVWM4MUFuTUdmTnhiczIwYXRaWjJmeFFKdSs1TEV5eHppUnhYcXRaMUZqOU5ESkt3aHJqY3RmdVpHVWZwR01ISHFSUU0vNW53bXBCTTFrVFQ2QkFZVS81ODdTR09jdFFPa2NheXBxRllaTVd6RVJqak5qZ2k2OGNHOWdvQT09PC9kczpTaWduYXR1cmVWYWx1ZT4KPGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRHlqQ0NBcktnQXdJQkFnSUpBSk5PRnVRZDcyN2NNQTBHQ1NxR1NJYjNEUUVCQlFVQU1Fd3hDekFKQmdOVkJBWVRBbEpUTVJFd0R3WURWUVFJRXdoQ1pXeG5jbUZrWlRFU01CQUdBMVVFQ2hNSlRHbG5hSFJUUVUxTU1SWXdGQVlEVlFRREV3MXNhV2RvZEhOaGJXd3VZMjl0TUI0WERURTFNRGt4TXpFNU1ERTBNRm9YRFRJMU1Ea3hNREU1TURFME1Gb3dUREVMTUFrR0ExVUVCaE1DVWxNeEVUQVBCZ05WQkFnVENFSmxiR2R5WVdSbE1SSXdFQVlEVlFRS0V3bE1hV2RvZEZOQlRVd3hGakFVQmdOVkJBTVREV3hwWjJoMGMyRnRiQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUM3cFVLT1BNeUUyb1NjSExQR0pGVGVwSzlqMUgwM2Uvcy9Xbk9Odzhad1lCYUJJWUlRdVg2dUU4akZQZEQwdVFTYVlwT3c1aDVUZ3E2eEJWN20ya1BPNTNoczhnRUdXUmJDZEN0eGk5RU1Kd0lPWXIraXNHME4rRHZWOUt5YkpmNnRxY001MFBpRmpWTnRmeDhJdWJNcEFLQ2JxdWFxZExhSEgwcmdQMWhiZ25HbTVZWmt5RUs0czh4dUxVRFM2cUw3TjdhL2V6MlprNDV1M0wzcUZjdW5jUEk1QlRuSmc2ZnFseXBEaENET0JJNUxqdzEwSG1nWkhQSVh6T2hFUFZWK3JYMmlIaEY0Vjl2ekVvZUlVQUJZWFFWTlJSTkhwUGRWc0s2aVRUa3l2YnJHSi90djNvRlpoTk9TTDBLdXkrUTlubEU5ZkVGcXlVeWRKNjd2c1hxWkFnTUJBQUdqZ2E0d2dhc3dIUVlEVlIwT0JCWUVGSFBUNkV5MXFneE16TUl0MmQzT1d1d3pmUFNVTUh3R0ExVWRJd1IxTUhPQUZIUFQ2RXkxcWd4TXpNSXQyZDNPV3V3emZQU1VvVkNrVGpCTU1Rc3dDUVlEVlFRR0V3SlNVekVSTUE4R0ExVUVDQk1JUW1Wc1ozSmhaR1V4RWpBUUJnTlZCQW9UQ1V4cFoyaDBVMEZOVERFV01CUUdBMVVFQXhNTmJHbG5hSFJ6WVcxc0xtTnZiWUlKQUpOT0Z1UWQ3MjdjTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBSGtIdHdKQm9lT2h2cjA2TTBNaWtLYzk5emU2VHFBR3ZmK1FrZ0ZvVjFzV0dBaDNOS2NBUitYU2xmSytzUVdySEdraWlhNWhXS2dBUE1NVWJrTFA5REZXa2piSzI0MWlzQ1paRC9MdkExYW5iVis3UGlkbitzd1o1ZFI3eW5YMnZqMGtGWWIrVnNHUGthdk5jajhSTi9EZHVoTi9UbWk1c1FBbFdoYXcwNlVBZUVxWHRGZUxiVGdMZmZCYWo3UG1SMElZanZUWkEwWDJGZFJ1MEdYUnhuN3pnaGpwdlNxOW51V2EzcEdiZmRWdEw2R0lrd1lVUGNEempyNE9lR1hObUlaZS93TUNuejZWR1pZK0xVZ3ppLzREQUM2VjNPak11aGRxUy8yK28xK0NYQ3dOMDhDSUhRVjYrQVVCZW5FVmF3TXNpYWRMQmd4M2tGZTVpWHJZUk1BPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxTdWJqZWN0PjxOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPm93bmVyQGNvbXBhbnkuY29tPC9OYW1lSUQ+PC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyNi0wNC0wNVQwNjozMjo1NFoiIE5vdE9uT3JBZnRlcj0iMjAyNi0wNC0wNVQwNzozNzo1NFoiPjxBdWRpZW5jZVJlc3RyaWN0aW9uPjxBdWRpZW5jZT5odHRwOi8vbG9jYWxob3N0Ojg4ODcvcHJvamVjdHM8L0F1ZGllbmNlPjwvQXVkaWVuY2VSZXN0cmljdGlvbj48L0NvbmRpdGlvbnM+PEF0dHJpYnV0ZVN0YXRlbWVudD48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI+PEF0dHJpYnV0ZVZhbHVlPm93bmVyQGNvbXBhbnkuY29tPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9InNlc3Npb25fZHVyYXRpb25fdHlwZSI+PEF0dHJpYnV0ZVZhbHVlPmxvbmc8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjwvQXR0cmlidXRlU3RhdGVtZW50PjwvQXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+Cg=='
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

        $this->assertSame('http://localhost:8887/projects', $url);
    }

    public function testTamperedResponseIsRejected()
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML signature verification failed');

        $xml = base64_decode($this->raw_saml_response['SAMLResponse']);
        $xml = str_replace('owner@company.com', 'tampered@company.com', $xml);
        $tampered_payload = ['SAMLResponse' => base64_encode($xml)];

        $this->saml_utils->parseSamlResponse(
            $tampered_payload,
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }

    public function testMissingSignatureIsRejected()
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML response is not signed.');

        $xml = base64_decode($this->raw_saml_response['SAMLResponse']);
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

    public function testWrongCertificateIsRejected()
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML signature verification failed');

        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => 'wrong-idp'], $res);
        $x509 = openssl_csr_sign($csr, null, $res, 1);
        openssl_x509_export($x509, $wrong_certificate);

        $this->saml_utils->parseSamlResponse(
            $this->raw_saml_response,
            $wrong_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }

    public function testExpiredAssertionIsRejected()
    {
        $this->expectException(InvalidSamlResponseException::class);
        $this->expectExceptionMessage('SAML assertion has expired.');

        $parsed_response = $this->saml_utils->parseSamlResponse(
            $this->raw_saml_response,
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

    public function testWrongDestinationIsRejected()
    {
        $this->expectException(InvalidSamlResponseException::class);
        $this->expectExceptionMessage('SAML response destination mismatch.');

        $this->saml_utils->parseSamlResponse(
            $this->raw_saml_response,
            $this->idp_certificate,
            'http://wrong-destination.com',
            'http://localhost:8887/projects'
        );
    }

    public function testWrongAudienceIsRejected()
    {
        $this->expectException(InvalidSamlResponseException::class);
        $this->expectExceptionMessage('SAML assertion audience mismatch.');

        $this->saml_utils->parseSamlResponse(
            $this->raw_saml_response,
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://wrong-audience.com'
        );
    }

    public function testSha1IsRejected()
    {
        $this->expectException(InvalidSamlSignatureException::class);
        $this->expectExceptionMessage('SAML signature verification failed: Weak algorithm');

        $xml = base64_decode($this->raw_saml_response['SAMLResponse']);
        $xml = str_replace(
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            $xml
        );
        $weak_payload = ['SAMLResponse' => base64_encode($xml)];

        $this->saml_utils->parseSamlResponse(
            $weak_payload,
            $this->idp_certificate,
            'http://localhost:8887/projects',
            'http://localhost:8887/projects'
        );
    }
}
