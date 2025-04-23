<?php
/**
 * Cosmotown Domain Module for HostBill
 * Integrates with Cosmotown API for domain management
 *
 * @version 1.0.1 - Modified updateNameServers to return the array of nameservers.
 */

// Ensure this class extends the correct HostBill base class if needed.
// If 'DomainModule' is not automatically loaded, you might need:
// require_once HB_MODULES_DIR . '/domain/DomainModule.php';

class Cosmotown extends DomainModule {
    // Module metadata
    public $name = 'Cosmotown';
    public $description = 'Domain Registrar Module for Cosmotown';
    public $version = '1.0.1'; // Updated version number

    // Configuration settings
    protected $config = [
        'apiKey' => [
            'label' => 'Cosmotown API Key',
            'type' => 'text',
            'value' => '' // Default/Example value
        ],
        'endpoint' => [
            'label' => 'Cosmotown API Endpoint',
            'type' => 'text',
            'value' => 'https://cosmotown.com/v1' // Default value
        ],
        'couponId' => [
            'label' => 'Coupon ID (Optional)',
            'type' => 'text',
            'value' => ''
        ]
    ];

    // Supported commands - Ensure these match HostBill's expectations
    protected $commands = [
        'Register',
        'Transfer',   // Added stub
        'Renew',      // Added stub
        'updateNameServers',
        'getNameServers',
        'getEppCode',
        'testConnection',
        'getDomainStatus'
        // Consider adding: 'getContactDetails', 'updateContactDetails', 'getRegistrarLock', 'updateRegistrarLock' if needed
    ];

    // Hold the API client instance
    private $api = null;

    /**
     * Initialize API client configuration
     * @return object API configuration object
     */
    private function api() {
        if ($this->api === null) {
            // Use stdClass for simplicity, or create a dedicated API client class
            $this->api = new stdClass();
            // Ensure endpoint value doesn't have trailing slashes for clean path concatenation
            $this->api->baseUrl = rtrim($this->config['endpoint']['value'] ?? 'https://cosmotown.com/v1', '/');
            $this->api->apiKey = trim($this->config['apiKey']['value'] ?? '');
        }
        return $this->api;
    }

    /**
     * Make API request to Cosmotown
     * @param string $method HTTP method (GET, POST, etc.)
     * @param string $path API endpoint path (e.g., '/reseller/domaininfo')
     * @param array $data Request data (for POST/PUT requests)
     * @return array API response decoded as an array, plus HTTP metadata
     */
    private function apiRequest($method, $path, $data = []) {
        $apiUrl = $this->api()->baseUrl . $path;
        $apiKey = $this->api()->apiKey;

        if (empty($apiKey)) {
            $this->addError('Cosmotown API Key is not configured.');
            return ['success' => false, 'http_code' => 0, 'message' => 'API Key missing'];
        }

        $headers = [
            'X-API-TOKEN: ' . $apiKey,
            'Content-Type: application/json',
            'Accept: application/json'
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $apiUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_HEADER, true); // Include headers in the output
        curl_setopt($ch, CURLOPT_TIMEOUT, 30); // Increased timeout
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); // Should be true in production
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        if (!empty($data) && in_array(strtoupper($method), ['POST', 'PUT', 'PATCH'])) {
            $payload = json_encode($data);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            $headers[] = 'Content-Length: ' . strlen($payload); // Good practice
        } else {
             // Ensure Content-Length is 0 for GET/DELETE if Content-Type is set,
             // though often not strictly needed for GET/DELETE.
             // $headers[] = 'Content-Length: 0';
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        // Log the request being sent
        $this->logAction([
            'action' => 'Cosmotown API Request',
            'method' => $method,
            'url' => $apiUrl,
            'headers' => $headers, // Be careful logging headers containing API keys in production logs
            'request_data' => $data // Sensitive data might be logged here
        ]);

        $rawResponse = curl_exec($ch);
        $curlError = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        if ($rawResponse === false) {
            $errorMsg = 'Curl error: ' . $curlError;
            $this->addError($errorMsg);
            $this->logAction([
                'action' => 'Cosmotown API Curl Error',
                'method' => $method,
                'url' => $apiUrl,
                'error' => $errorMsg
            ]);
            return ['success' => false, 'http_code' => 0, 'message' => $errorMsg];
        }

        $responseHeaders = substr($rawResponse, 0, $headerSize);
        $responseBody = substr($rawResponse, $headerSize);

        $result = json_decode($responseBody, true);

        // If JSON decoding fails, keep the raw body for debugging
        if ($result === null && json_last_error() !== JSON_ERROR_NONE) {
            $result = ['raw_body' => $responseBody];
            $jsonError = json_last_error_msg();
            $result['json_decode_error'] = $jsonError;
             // Don't automatically assume failure, some successful API calls might return non-JSON
        }

        // Add metadata to the result array
        $result['http_code'] = $httpCode;
        $result['raw_headers'] = $responseHeaders;
         // Add raw_body only if it wasn't the primary result due to decode failure
        if (!isset($result['raw_body'])) {
            $result['raw_body'] = $responseBody;
        }


        // Determine success based on HTTP code - adjust ranges as needed
        if ($httpCode >= 200 && $httpCode < 300) {
            // Check if the API itself indicates an error despite 2xx code
             if (isset($result['success']) && $result['success'] === false) {
                 $result['message'] = $result['message'] ?? 'API indicated failure despite HTTP 2xx.';
             } else {
                // Only set top-level success if not explicitly false in response body
                $result['success'] = $result['success'] ?? true;
             }
        } else {
            $result['success'] = false;
            // Try to get a meaningful error message from the response body
            $result['message'] = $result['message'] ?? $result['error'] ?? 'HTTP Error ' . $httpCode;
        }

        // Log the response received
        $this->logAction([
            'action' => 'Cosmotown API Response',
            'method' => $method,
            'url' => $apiUrl,
            'http_code' => $httpCode,
            'response' => $result // Sensitive data might be logged here
        ]);

        return $result;
    }

    /**
     * Test connection to the Cosmotown API
     * Attempts to fetch info for a non-existent domain; expects success or auth error.
     * @return bool True if connection/authentication seems okay, false otherwise.
     */
    public function testConnection() {
        // Using a likely non-existent .com domain for testing basic auth/connectivity
        $response = $this->apiRequest('GET', '/reseller/domaininfo?domain=testconnection-hostbill.com');

        // 200 OK means connected and authenticated, domain info (likely not found) returned.
        // 403 Forbidden likely means authenticated but maybe IP restricted or lacks permission for *that* domain (still proves API key works).
        // 404 Not Found could also mean authenticated but domain doesn't exist under the reseller account.
        // 401 Unauthorized means the API key is wrong.
        if ($response['http_code'] == 200 || $response['http_code'] == 403 || $response['http_code'] == 404) {
            $this->addInfo('Successfully connected to Cosmotown API. Key appears valid (Response code: ' . $response['http_code'] . ').');
            return true;
        } else {
             $error = 'Failed to connect/authenticate with Cosmotown API. ';
             if ($response['http_code'] === 401) {
                 $error .= 'Received HTTP 401 Unauthorized - Please check your API Key.';
             } elseif ($response['http_code'] > 0) {
                $error .= 'Received HTTP ' . $response['http_code'] . '. Response: ' . ($response['message'] ?? $response['raw_body'] ?? 'No details');
             } else {
                 $error .= 'Error: ' . ($response['message'] ?? 'Unknown connection error.');
             }
             $this->addError($error);
             return false;
        }
    }

    /**
     * Register a domain
     * @return bool True on success, false on failure.
     */
    public function Register() {
        $domain = $this->options['sld'] . '.' . $this->options['tld'];
        $years = $this->options['numyears'] ?? 1;
        $couponId = trim($this->config['couponId']['value'] ?? '');

        $data = [
            'items' => [
                [
                    'name' => $domain,
                    'years' => (int)$years
                    // Add contact details here if required by the API for registration
                    // 'registrant' => [...], 'admin' => [...], etc.
                ]
            ]
        ];

        if (!empty($couponId)) {
            $data['coupon_id'] = $couponId;
        }

        // Note: Assumes nameservers are set separately or default Cosmotown NS are used.
        // If specific NS need to be set during registration, add them to the 'items' payload
        // based on Cosmotown API docs. Example: 'nameservers' => ['ns1.example.com', ...]

        $response = $this->apiRequest('POST', '/reseller/registerdomains', $data);

        // Check if the response itself is an array (expected structure) and HTTP code is 200
        if ($response['http_code'] == 200 && isset($response['success']) && $response['success'] === true && is_array($response)) {
            // Cosmotown API might return an array of results, one for each domain requested
            // Find the result for the specific domain we registered
            $domainResult = null;
            // The exact structure of the success response needs verification from API docs.
            // Assuming it's an array where each element has 'domain' and 'status' keys.
            // Adjust this loop based on the actual API response format.
            if (isset($response['results']) && is_array($response['results'])) { // Example structure
                 foreach ($response['results'] as $item) {
                     if (isset($item['domain']) && strtolower($item['domain']) === strtolower($domain)) {
                         $domainResult = $item;
                         break;
                     }
                 }
            } elseif (isset($response['domain']) && strtolower($response['domain']) === strtolower($domain)) { // Simpler structure?
                 $domainResult = $response;
            }


            if ($domainResult) {
                // Check the status reported by the API for this domain
                 // Adjust 'Registered' based on actual success status string from API
                if (isset($domainResult['status']) && $domainResult['status'] === 'Registered') {
                    // Try to get actual dates, otherwise estimate
                    $details = $this->getDomainDetails($domain); // Fetch details to get accurate dates
                    $regDate = $details['created'] ?? date('Y-m-d H:i:s');
                    // Ensure expiration_date format is correct (YYYY-MM-DD HH:MM:SS)
                    $expDate = $details['expiration_date'] ?? date('Y-m-d H:i:s', strtotime("+$years years"));

                    $this->addDomain('Active', [
                        'reg_date' => $regDate,
                        'exp_date' => $expDate
                    ]);
                    $this->addInfo($domainResult['message'] ?? 'Domain registered successfully.');
                    $this->logAction([
                        'action' => 'Register Domain', 'result' => true, 'domain' => $domain,
                        'reg_date' => $regDate, 'exp_date' => $expDate, 'error' => false
                    ]);
                    return true;
                } else {
                    // API returned 200, but status for the domain indicates failure/pending
                    $error = $domainResult['message'] ?? 'API reported registration status: ' . ($domainResult['status'] ?? 'Unknown');
                    $this->addError($error);
                    $this->logAction(['action' => 'Register Domain', 'result' => false, 'domain' => $domain, 'error' => $error]);
                    return false;
                }
            } else {
                 // API returned 200 OK but didn't include results for our domain?
                 $this->addError('Registration response successful (HTTP 200) but did not contain results for domain: ' . $domain);
                 return false;
            }
        } else {
            // HTTP error or API indicated failure
            $error = $response['message'] ?? 'Failed to register domain. Response: ' . ($response['raw_body'] ?? 'No body');
            $this->addError($error);
            $this->logAction(['action' => 'Register Domain', 'result' => false, 'domain' => $domain, 'error' => $error]);
            return false;
        }
    }

    /**
     * Get domain details (created, expiration dates, status, nameservers etc.)
     * @param string $domain Domain name
     * @return array|bool Domain details array on success, false on failure.
     */
    private function getDomainDetails($domain) {
        $url = '/reseller/domaininfo?domain=' . urlencode($domain);
        $response = $this->apiRequest('GET', $url);

        // Check for successful HTTP code and if the expected 'domain' key exists
        if ($response['http_code'] == 200 && isset($response['success']) && $response['success'] === true && isset($response['domain']) && is_array($response['domain'])) {
            // The API nests the details inside a 'domain' key
             return $response['domain'];
        }

        // Log failure if details couldn't be retrieved
        $this->logAction([
            'action' => 'Get Domain Details Failed',
            'domain' => $domain,
            'result' => false,
            'response_code' => $response['http_code'] ?? 'N/A',
            'error' => $response['message'] ?? 'Failed to retrieve domain details or unexpected format.',
            'response_body' => $response['raw_body'] ?? null // Log raw body on error
        ]);
        return false;
    }

    /**
     * Get domain status (e.g., Active, Pending, Expired) for HostBill
     * @return string|bool HostBill status string ('Active', 'Pending', 'Expired') or false on failure.
     */
    public function getDomainStatus() {
        $domain = $this->options['sld'] . '.' . $this->options['tld'];
        $details = $this->getDomainDetails($domain);

        if ($details) {
            // Determine HostBill status based on details from Cosmotown
            // This logic might need adjustment based on specific statuses returned by Cosmotown API
            $apiStatus = strtolower($details['status'] ?? 'unknown'); // e.g., 'active', 'expired', 'redemption', 'pending_transfer'

            $status = 'Pending'; // Default
            if ($apiStatus === 'active' || $apiStatus === 'ok') {
                 // Check if locked - HostBill often shows 'Active' for locked domains.
                 // Use 'locked' field if available, otherwise assume active if status is ok/active.
                 $status = (isset($details['locked']) && $details['locked']) ? 'Active' : 'Active'; // Or 'Unlocked' if you prefer distinction
            } elseif ($apiStatus === 'expired' || $apiStatus === 'redemption period' || $apiStatus === 'pending delete') {
                $status = 'Expired';
            } elseif ($apiStatus === 'pending transfer' || $apiStatus === 'pending') {
                $status = 'Pending';
            }
            // Add more mappings as needed based on Cosmotown API status codes

            $this->logAction([
                'action' => 'Get Domain Status', 'domain' => $domain,
                'api_status' => $apiStatus, 'hostbill_status' => $status, 'result' => true
            ]);
            return $status;
        }

        $this->addError('Failed to retrieve domain details to determine status for ' . $domain);
        return false; // Indicate failure to HostBill
    }

    /**
     * Update domain nameservers
     * @return array|bool Returns the array of nameservers on success for HostBill, or false on failure.
     */
    public function updateNameServers() {
        $domain = $this->options['sld'] . '.' . $this->options['tld'];
        $nameservers_input = []; // Collect NS from options
        for ($i = 1; $i <= 4; $i++) { // Check up to 4 nameservers from HostBill options
            $ns = trim(strtolower($this->options["ns{$i}"] ?? ''));
            if (!empty($ns)) {
                $nameservers_input[] = $ns;
            }
        }

        // Ensure at least two nameservers are provided if required by registrar rules (Cosmotown might enforce this)
        if (count($nameservers_input) < 2) {
             $this->addError('Please provide at least two nameservers.');
             // Optionally log this user error
             return false; // Return false to indicate failure to HostBill
        }

        $data = [
            'domain' => $domain,
            'nameservers' => $nameservers_input // Send the collected nameservers
        ];

        // Log the request being prepared
        $this->logAction([
            'action' => 'Update Name Servers - Preparing Request',
            'domain' => $domain,
            'options_provided' => [ // Log what HostBill provided
                'ns1' => $this->options['ns1'] ?? '', 'ns2' => $this->options['ns2'] ?? '',
                'ns3' => $this->options['ns3'] ?? '', 'ns4' => $this->options['ns4'] ?? ''
            ],
            'nameservers_being_sent' => $nameservers_input
        ]);

        // Make the API call to update nameservers
        $response = $this->apiRequest('POST', '/reseller/savedomainnameservers', $data);

        // Check for successful HTTP code and API success indication
        if ($response['http_code'] == 200 && isset($response['success']) && $response['success'] === true) {
            // Update the internal $this->options state to match what was sent
            // This might be used by HostBill or subsequent module actions within the same request
            for ($i = 0; $i < 4; $i++) {
                $this->options["ns" . ($i + 1)] = $nameservers_input[$i] ?? '';
            }

            $this->logAction([
                'action' => 'Update Name Servers - Success',
                'domain' => $domain,
                'options_after_internal_update' => [ // Log the state after internal update
                    'ns1' => $this->options['ns1'], 'ns2' => $this->options['ns2'],
                    'ns3' => $this->options['ns3'], 'ns4' => $this->options['ns4']
                 ],
                'result' => true,
                'response' => $response // Log success response
            ]);

            $this->addInfo('Nameservers update request sent successfully to Cosmotown.');

            // *** CHANGE: Return the array of nameservers that were successfully sent ***
            // This allows HostBill to update its display/database immediately
            $updated_nameservers_return = [];
            for ($i = 1; $i <= 4; $i++) {
                $updated_nameservers_return["ns{$i}"] = $this->options["ns{$i}"]; // Use the updated options
            }
            return $updated_nameservers_return;

        } else {
            // Handle API or HTTP errors
            $error = $response['message'] ?? 'Failed to update nameservers on Cosmotown. Response: ' . ($response['raw_body'] ?? 'No body');
            $this->addError($error);
            $this->logAction([
                'action' => 'Update Name Servers - Failed',
                'domain' => $domain,
                'nameservers_sent' => $nameservers_input,
                'result' => false,
                'error' => $error,
                'response_code' => $response['http_code'] ?? 'N/A',
                'response_body' => $response['raw_body'] ?? null
            ]);
            return false; // Return false to HostBill on failure
        }
    }

    /**
     * Get current domain nameservers from the registrar
     * Includes retry logic for potential propagation delays.
     * @return array|bool Array of nameservers ['ns1'=>..., 'ns2'=>...] or false on failure.
     */
    public function getNameServers() {
        $domain = $this->options['sld'] . '.' . $this->options['tld'];

        $maxRetries = 3; // Reduced retries, increase if needed
        $retryDelay = 2; // Seconds between retries

        for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
             $details = $this->getDomainDetails($domain); // Use the centralized details fetcher

             if ($details && isset($details['nameservers']) && is_array($details['nameservers'])) {
                 $nameservers = [];
                 // Populate ns1 to ns4 based on the fetched array
                 for ($i = 0; $i < 4; $i++) {
                     $nameservers["ns" . ($i + 1)] = $details['nameservers'][$i] ?? '';
                 }

                 $this->logAction([
                     'action' => 'Get Name Servers - Success',
                     'domain' => $domain,
                     'nameservers_found' => $nameservers,
                     'result' => true,
                     'attempt' => $attempt
                 ]);
                 return $nameservers; // Return the formatted array
             } else {
                 // Log the reason for retry/failure on this attempt
                 $errorReason = 'Failed to get details or nameservers missing/invalid format in response.';
                 if (!$details) $errorReason = 'getDomainDetails failed.';

                 $this->logAction([
                     'action' => 'Get Name Servers - Attempt Failed',
                     'domain' => $domain,
                     'attempt' => $attempt,
                     'max_retries' => $maxRetries,
                     'error' => $errorReason,
                     'details_response' => $details // Log what getDomainDetails returned (or false)
                 ]);

                 // Don't retry if it's the last attempt
                 if ($attempt < $maxRetries) {
                     sleep($retryDelay);
                 }
             }
        } // End retry loop

      
    }


    /**
     * Get domain EPP (Authorization) code
     * @return string|bool EPP code string on success, false on failure.
     */
    public function getEppCode() {
        $domain = $this->options['sld'] . '.' . $this->options['tld'];
        $url = '/reseller/domainepp?domain=' . urlencode($domain);
        $response = $this->apiRequest('GET', $url);

        // Check for successful HTTP code and presence of 'auth_code'
        if ($response['http_code'] == 200 && isset($response['success']) && $response['success'] === true && isset($response['auth_code'])) {
            $eppCode = $response['auth_code'];
            if (!empty($eppCode)) {
                 $this->addInfo('EPP code retrieved successfully.');
                 $this->logAction(['action' => 'Get EPP Code', 'result' => true, 'domain' => $domain]);
                 return $eppCode; // Return the EPP code string
            } else {
                 $error = 'API reported success but EPP code was empty.';
                 $this->addError($error);
                 $this->logAction(['action' => 'Get EPP Code', 'result' => false, 'domain' => $domain, 'error' => $error, 'response' => $response]);
                 return false;
            }
        } else {
            $error = $response['message'] ?? 'Failed to retrieve EPP code. Response: ' . ($response['raw_body'] ?? 'No body');
            $this->addError($error);
            $this->logAction([
                'action' => 'Get EPP Code', 'result' => false, 'domain' => $domain,
                'error' => $error, 'response_code' => $response['http_code'] ?? 'N/A',
                'response' => $response
            ]);
            return false;
        }
    }

    /**
     * Renew domain (Stub - Requires Implementation)
     * @return bool True on success, false on failure.
     */
    public function Renew() {
        $domain = $this->options['sld'] . '.' . $this->options['tld'];
        $years = $this->options['numyears'] ?? 1;
        $couponId = trim($this->config['couponId']['value'] ?? '');

        $this->addError('Renew function is not yet implemented for the Cosmotown module.');
        $this->logAction(['action' => 'Renew Attempt (Not Implemented)', 'domain' => $domain, 'years' => $years]);

        // TODO: Implement API call to Cosmotown's renewal endpoint
        // $data = [ 'domain' => $domain, 'years' => $years, ... ];
        // if (!empty($couponId)) $data['coupon_id'] = $couponId;
        // $response = $this->apiRequest('POST', '/reseller/renewdomain', $data); // Replace with actual endpoint
        // Handle response, update expiry date using $this->addDomain() if successful

        return false; // Return false until implemented
    }

    /**
     * Transfer domain (Stub - Requires Implementation)
     * @return bool True on success, false on failure.
     */
    public function Transfer() {
        $domain = $this->options['sld'] . '.' . $this->options['tld'];
        $eppCode = $this->options['eppcode'] ?? ''; // Get EPP code from HostBill options
        $years = $this->options['numyears'] ?? 1; // Usually 1 year for transfers
        $couponId = trim($this->config['couponId']['value'] ?? '');

        if (empty($eppCode)) {
             $this->addError('EPP code is required for domain transfer.');
             return false;
        }

        $this->addError('Transfer function is not yet implemented for the Cosmotown module.');
        $this->logAction(['action' => 'Transfer Attempt (Not Implemented)', 'domain' => $domain]);

        // TODO: Implement API call to Cosmotown's transfer initiation endpoint
        // $data = [ 'domain' => $domain, 'auth_code' => $eppCode, 'years' => $years, ... ]; // Add contacts if needed
        // if (!empty($couponId)) $data['coupon_id'] = $couponId;
        // $response = $this->apiRequest('POST', '/reseller/transferdomain', $data); // Replace with actual endpoint
        // Handle response (transfers are often asynchronous, might just return pending)

        return false; // Return false until implemented
    }

    // Consider adding other standard DomainModule functions as needed:
    // public function getContactDetails() {}
    // public function updateContactDetails() {}
    // public function getRegistrarLock() {}
    // public function updateRegistrarLock() {}
    // public function Sync() {} // For syncing expiry date and status

} // End Class Cosmotown
