package c8y.lwm2m.weptech.action;

import com.cumulocity.microservice.customdecoders.api.exception.DecoderServiceException;
import com.cumulocity.microservice.customdecoders.api.model.DecoderResult;
import com.cumulocity.microservice.customdecoders.api.service.DecoderService;
import com.cumulocity.microservice.customdecoders.api.util.DecoderUtils;
import com.cumulocity.model.idtype.GId;
import com.cumulocity.model.measurement.MeasurementValue;
import com.cumulocity.rest.representation.measurement.MeasurementCollectionRepresentation;
import com.cumulocity.rest.representation.measurement.MeasurementRepresentation;
import com.cumulocity.sdk.client.inventory.InventoryApi;
import com.cumulocity.sdk.client.measurement.MeasurementApi;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;

import com.cumulocity.microservice.context.ContextService;
import com.cumulocity.microservice.context.credentials.MicroserviceCredentials;
import com.cumulocity.sdk.client.RestConnector;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import java.math.BigDecimal;

import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.DateTimeFormat;
import java.util.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;



import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.StringReader;

import com.cumulocity.model.ID;
import com.cumulocity.rest.representation.identity.ExternalIDRepresentation;
import com.cumulocity.sdk.client.identity.IdentityApi;
import  com.cumulocity.rest.representation.inventory.ManagedObjectRepresentation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


//@Component
@Slf4j
@Service
public class OMSDecoderC8YParserService implements DecoderService{

    @Autowired
    IdentityApi identityApi;

    @Autowired
    InventoryApi inventoryApi;

    @Autowired
    MeasurementApi measurementApi;

    private final RestConnector restConnector;
    private final ContextService<MicroserviceCredentials> contextService;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final String baseUrl;

    // Use the explicit internal reverse-proxy path target registered via your cumulocity.json manifest
    private static final String PARSER_INTERNAL_PATH = "/service/c8y-oms-parser/api/v1/parse";

    // Bound the parser call so a hanging parser cannot block request threads forever
    private static final Duration PARSER_CONNECT_TIMEOUT = Duration.ofSeconds(5);
    Duration parserRequestTimeout = Duration.ofSeconds(15);

    @Autowired
    public OMSDecoderC8YParserService(RestConnector restConnector,
                                      ContextService<MicroserviceCredentials> contextService) {
        this(restConnector, contextService,
                HttpClient.newBuilder()
                        .version(HttpClient.Version.HTTP_1_1)
                        .connectTimeout(PARSER_CONNECT_TIMEOUT)
                        .build(),
                System.getenv("C8Y_BASEURL"));
    }

    OMSDecoderC8YParserService(RestConnector restConnector,
                               ContextService<MicroserviceCredentials> contextService,
                               HttpClient httpClient,
                               String baseUrl) {
        this.restConnector = restConnector;
        this.contextService = contextService;
        this.objectMapper = new ObjectMapper();
        this.httpClient = httpClient;
        this.baseUrl = baseUrl;
    }

    @Override
    public DecoderResult decode(String payloadToDecode, GId sourceDeviceId, Map<String, String> inputArguments) throws DecoderServiceException {
        DecoderResult decoderResult = new DecoderResult();
        String decodedString = "";
        String meterSerial = "";
        String meterPayload = "";
        String meterEncryptionkey = "";
        Long meterOmsMode = null;
        final String EXTERNAL_ID_TYPE = "c8y_Serial";
        final String ENCRYPTION_KEY_TYPE = "meter_encryption_key";
        final String OMS_MODE = "oms_mode";

        log.info("Decoding OMS payload HEX {}.", payloadToDecode);

       byte[] decodedBytes = DecoderUtils.hexStringToByteArray(payloadToDecode);

       try {
           decodedString = new String(decodedBytes, "US-ASCII");

           log.info("Decoding OMS payload String {}.", decodedString);

           //extract meter data
           CSVParser parser = CSVFormat.DEFAULT.parse(new StringReader(decodedString));
           List<CSVRecord> records = parser.getRecords();

           // fields 7 (serial) and 8 (payload) are required
           if (records.isEmpty() || records.get(0).size() < 9) {
               log.error("Extracted Meter Payload from Weptech GW is less than 9 elements.");
               return decoderResult;
           }

           CSVRecord record = records.get(0);

           meterSerial = record.get(7);
           meterPayload = record.get(8);

           log.info("Meter Serial ID {}, Meter Payload {}", meterSerial, meterPayload);

           // Get Meter's Managed Object ID
           ManagedObjectRepresentation  meterMO = getDeviceByExternalId(EXTERNAL_ID_TYPE, meterSerial);

           if (meterMO != null) {
               // check if meter has encryption key
               meterEncryptionkey =  (String)meterMO.get(ENCRYPTION_KEY_TYPE);
               meterOmsMode = toOmsMode(meterMO.get(OMS_MODE));

               if (meterOmsMode == null ) {
                   log.error("There is no OMS Mode configured for Meter with Serial {}", meterSerial);
                   throw new DecoderServiceException(new Throwable("There is no OMS Mode configured for the Meter"), "There is no OMS Mode configured for the Meter",decoderResult );

               }

               String responseBody = null;

               if(meterEncryptionkey != null && !meterEncryptionkey.trim().isEmpty()) {
                   log.info("There is Encryption Key for the meter {}", meterEncryptionkey);
                   //decrypt meter payload using key
                   //meterPayload = dyecryptMeterPauload(meterEncryptionkey, meterPayload);

                   //log.info("Decrypted payload for meter {} is {}",meterSerial ,meterPayload);
                   // call C8Y OMS parser
                    responseBody = parseOMSPayload(meterPayload, meterEncryptionkey, meterOmsMode.longValue());
               } else {
                   log.info("There is no Encryption Key for the meter");
                   responseBody = parseOMSPayload(meterPayload, null, meterOmsMode.longValue());
               }

               // parse response body
               parsewMbusPayload(meterMO, responseBody);

           }

           log.info("Meter MO {}", meterMO);


       } catch (java.io.UnsupportedEncodingException e) {
           throw new DecoderServiceException(new Throwable("Unsupported Encoding"), "Unsupported Encoding US-ASCII", decoderResult);
       }  catch (java.io.IOException e) {
           throw new DecoderServiceException(new Throwable("IO Exception"), "IO Exception from parsing Weptech payload", decoderResult);
       }


        log.info("Finished decoding OMS Payload");
        return decoderResult;

    }

    // oms_mode may be stored as any JSON number or as a string
    static Long toOmsMode(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Long.parseLong(text.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private  String parseOMSPayload(String payloadToDecode, String encryptionKey, long omsMode) throws DecoderServiceException {

        MicroserviceCredentials credentials = contextService.getContext();
        if (credentials == null) {
            throw new IllegalStateException("Execution thread must be running within an active Cumulocity tenant context.");
        }

        HttpResponse<String> response;
        try {
            ObjectNode requestBody = objectMapper.createObjectNode();
            requestBody.put("payload", payloadToDecode);

            if (encryptionKey != null) {
                requestBody.put("encryptionkey", encryptionKey);
            }
            requestBody.put("oms_mode", omsMode);

            String dynamicJsonBody = objectMapper.writeValueAsString(requestBody);

            log.info("Invoking custom c8y-oms-parser via native Java HttpClient...");
            log.info("Sending payload to parser microservice...");

            // 1. Manually build the standard Cumulocity Basic Auth token: tenant/username:password
            String authString = credentials.getTenant() + "/" + credentials.getUsername() + ":" + credentials.getPassword();
            String encodedAuth = Base64.getEncoder().encodeToString(authString.getBytes(StandardCharsets.UTF_8));
            String basicAuthHeader = "Basic " + encodedAuth;
            //String constantJsonBody = "{\"payload\": \"YUQJB3RFcgkgB3pKEAAABG0NCl02BCCgNUcBBBMAAAAABJM7AAAAAASTPAAAAAACOwAAAlnw2ERtAABBNkQTAAAAAESTOwAAAABEkzwAAAAANP0XAQAAAAQkVzNHAQH9dGE=\"}";

            log.info("Base URL is ===> : " + baseUrl);

            // 2. Build the request forwarding the token to the local sidecar proxy
            HttpRequest request = HttpRequest.newBuilder()
                    //.uri(URI.create("http://localhost/service/c8y-oms-parser/api/v1/decode"))
                    //.uri(URI.create(baseUrl + "/service/c8y-oms-parser/api/v1/decode"))
                    .uri(URI.create(baseUrl + PARSER_INTERNAL_PATH))
                    .timeout(parserRequestTimeout)
                    //.uri(URI.create("http://c8y-oms-parser/api/v1/decode"))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("Authorization", basicAuthHeader)
                    .header("X-Cumulocity-Application-Key", "c8y-oms-parser")
                    //.POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                    .POST(HttpRequest.BodyPublishers.ofString(dynamicJsonBody))
                    .build();

            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.error("CRITICAL EXCEPTION PASSED INSIDE COMMUNICATION LAYER: ", e);
            throw new DecoderServiceException(e, "Underlying communication failure: " + e.getMessage(), new DecoderResult());
        }

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            log.info("SUCCESS! Constant payload communication works. Response: {}", response.body());
            return response.body();
        }

        log.error("OMS Parser returned HTTP {}: {}", response.statusCode(), response.body());
        throw new DecoderServiceException(new Throwable("HTTP FAILURE CODE"), "HTTP FAILURE CODE: " + response.statusCode() + " | PROXY ERROR BODY: " + response.body(), new DecoderResult());
    }

    /*private  JSONObject extractTemperatureData(JSONObject payload) {
        JSONObject apl = payload.getJSONObject("APL");
        JSONObject deviceIdObj = apl.getJSONObject("DeviceId");

        // Extract DeviceId and DeviceType
        String deviceId = deviceIdObj.getString("DinAddress");
        String deviceType = deviceIdObj.getString("DeviceTypeByName");

        // Extract Temperature value and unit
        JSONArray drArray = apl.getJSONArray("DR");
        Float tempValue = null;
        String tempUnit = null;

        for (int i = 0; i < drArray.length(); i++) {
            JSONObject drItem = drArray.getJSONObject(i);
            if ("Instantaneous value".equals(drItem.getString("FunctionByName")) &&
                    "External temperature".equals(drItem.getString("Description"))) {
                tempValue = Float.parseFloat(drItem.getString("Value"));
                tempUnit = drItem.getString("Unit");
                break;
            }
        }

        // Build result JSON
        JSONObject result = new JSONObject();
        result.put("DeviceId", deviceId);
        result.put("DeviceType", deviceType);
        result.put("TemperatureValue", tempValue);
        result.put("TemperatureUnit", tempUnit);

        return result;
    }*/


    public ManagedObjectRepresentation getDeviceByExternalId(String type, String externalId) throws DecoderServiceException {
        ID extId = new ID(type, externalId);
        ManagedObjectRepresentation meterMO = null;
        GId ManagedObjectID = null;

        try {
            // 3. Query the Identity API
            ExternalIDRepresentation representation = identityApi.getExternalId(extId);

            // 4. Extract the internal Global ID (Device ID)
            ManagedObjectID = representation.getManagedObject().getId();

            // get Managed Object
            meterMO = inventoryApi.get(ManagedObjectID);


            log.info("Meter MO {}", meterMO);
        } catch (com.cumulocity.sdk.client.SDKException e) {
            if (e.getHttpStatus() == 404) {
                log.error("Meter is  not found the given External ID {}.", externalId);
                throw new DecoderServiceException(new Throwable("Meter is not found"), "Meter is not found", new DecoderResult());
            } else {
                throw new DecoderServiceException(e, e.getMessage(), new DecoderResult());
            }
        }
        return meterMO;
    }


    public void parsewMbusPayload(ManagedObjectRepresentation meterMO, String jsonString) throws DecoderServiceException {
        DateTimeFormatter formatter = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss");

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(jsonString);
            JsonNode drArray = root.at("/data/parsed_measurements");

            if (drArray.isArray()) {
                // Resolve Effective Timestamp (Fallback to reception time if payload omits 046D)
                DateTime effectiveTimestamp = DateTime.now();
                for (JsonNode node : drArray) {
                    String description = node.has("description") ? node.get("description").asText() : "";
                    String header = node.has("header_raw") ? node.get("header_raw").asText() : "";
                    String value = node.has("value") ? node.get("value").asText() : "";

                   // if ("Date and Time".equalsIgnoreCase(description) || "046D".equals(header)) {
                    if ("046D".equals(header)) {
                        if (!value.isEmpty() && !"Unset".equalsIgnoreCase(value)) {
                            try {
                                effectiveTimestamp = formatter.parseDateTime(value);
                                log.info("Extracted payload timestamp: {}", effectiveTimestamp);
                            } catch (Exception e) {
                                log.warn("Failed to parse date '{}', defaulting to now", value);
                            }
                        }
                        break;
                    }
                }

                //Process records dynamically
                List<MeasurementRepresentation> measurementsToSend = new ArrayList<>();
                for (JsonNode node : drArray) {
                    String description = node.has("description") ? node.get("description").asText() : "";
                    String header = node.has("header_raw") ? node.get("header_raw").asText() : "";
                    String value = node.has("value") ? node.get("value").asText() : "";
                    String unit = node.has("unit") ? node.get("unit").asText() : "";

                    // Skip non-numeric or uninitialized records
                    if (value.isEmpty() || "Unset".equalsIgnoreCase(value)) {
                        continue;
                    }

                    BigDecimal numericValue;
                    try {
                        numericValue = new BigDecimal(value);
                    } catch (NumberFormatException e) {
                        log.warn("Skipping non-numeric value for header {}: {}", header, value);
                        continue;
                    }

                    // Match by description (primary) or header code (fallback)
                    //if ("Volume".equalsIgnoreCase(description) || "0413".equals(header) || "0C13".equals(header)) {
                    if ("0413".equals(header) || "0C13".equals(header)) { // Volume
                        measurementsToSend.add(createMeasurement(
                                meterMO, "C8y_Meter_Volume", "Meter_Volume", "V", numericValue, unit, effectiveTimestamp
                        ));
                    }
                    //else if ("Operating Time".equalsIgnoreCase(description) || "0420".equals(header)) {
                    else if ("0420".equals(header)) { //Operating Time
                        measurementsToSend.add(createMeasurement(
                                meterMO, "C8y_Meter_Operating_Time", "Meter_Operating_Time", "Operating_Time", numericValue, unit, effectiveTimestamp
                        ));
                    }
                    //else if ("Current Flow".equalsIgnoreCase(description) || "Volume Flow".equalsIgnoreCase(description) || "023B".equals(header)) {
                    else if ("023B".equals(header)) { // Current Flow or Volume Flow
                        measurementsToSend.add(createMeasurement(
                                meterMO, "C8y_Meter_Volume_Flow", "Meter_Volume_Flow", "Flow", numericValue, unit, effectiveTimestamp
                        ));
                    }
                    //else if ("Flow Temperature".equalsIgnoreCase(description) || "0259".equals(header) || "0A5A".equals(header)) {
                    else if ("0259".equals(header) || "0A5A".equals(header)) { // Flow Temperature
                        measurementsToSend.add(createMeasurement(
                                meterMO, "C8y_Meter_Flow_Temperature", "Meter_Flow_Temperature", "T", numericValue, unit, effectiveTimestamp
                        ));
                    }
                    //else if ("Remaining Battery Lifetime".equalsIgnoreCase(description) || "01FD74".equals(header) || "02FD74".equals(header)) {
                    else if ( "01FD74".equals(header) || "02FD74".equals(header)) { //Remaining Battery Lifetime
                        measurementsToSend.add(createMeasurement(
                                meterMO, "C8y_Meter_Remaining_Battery", "Meter_Remaining_Battery", "Remaining_Battery", numericValue, unit, effectiveTimestamp
                        ));
                    }
                } // end of for

                if (measurementsToSend.isEmpty()) {
                    log.info("No supported measurements in payload, nothing to send");
                    return;
                }

                MeasurementCollectionRepresentation collection = new MeasurementCollectionRepresentation();
                collection.setMeasurements(measurementsToSend);
                measurementApi.createBulk(collection);
                log.info("Measurements are created successfully .....");

            } else {
                log.info("drArray is not an array");
            }

        } catch (Exception e) {
            log.error("Cannot Parse wMbus Payload.");
            throw new DecoderServiceException(e, e.getMessage(), new DecoderResult());

        }
    }

    /*public void parsewMbusPayload(ManagedObjectRepresentation meterMo, String jsonString) throws DecoderServiceException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(jsonString);
            //JsonNode drArray = root.at("/ParsedMeasurements");
            JsonNode drArray = root.at("/data/parsedMeasurements");

            MeasurementRepresentation volumeMeasurement = new MeasurementRepresentation();
            MeasurementRepresentation volumeFlowMeasurement = new MeasurementRepresentation();
            MeasurementRepresentation flowTemperatureMeasurement = new MeasurementRepresentation();
            MeasurementRepresentation remainingBatteryMeasurement = new MeasurementRepresentation();
            MeasurementRepresentation operatingTimeMeasurement = new MeasurementRepresentation();

            //Set source ID
            volumeMeasurement.setSource(meterMo);
            volumeFlowMeasurement.setSource(meterMo);
            flowTemperatureMeasurement.setSource(meterMo);
            remainingBatteryMeasurement.setSource(meterMo);
            operatingTimeMeasurement.setSource(meterMo);

            if (drArray.isArray()) {
                log.info("inside if  >>>>>>>>>>");
                for (JsonNode node : drArray) {
                    //log.info("inside for >>>>>>>>>>>>>>>");
                    //log.info("Node is  >>>>>>>>>>>>>>> {}", node);

                    String header = node.get("header_raw").asText();
                    String value = node.has("value") ? node.get("value").asText() : "";
                    String unit = node.has("unit") ? node.get("unit").asText() : "";

                    switch (header) {
                        case "046D": // 1. Date and Time
                            log.info("Date: {}", value);
                            //DateTime measurementTime = DateTime.now();
                            DateTimeFormatter formatter = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss");
                            DateTime measurementTime = formatter.parseDateTime(value);

                            volumeMeasurement.setDateTime(measurementTime);
                            volumeFlowMeasurement.setDateTime(measurementTime);
                            flowTemperatureMeasurement.setDateTime(measurementTime);
                            remainingBatteryMeasurement.setDateTime(measurementTime);
                            operatingTimeMeasurement.setDateTime(measurementTime);
                            log.info("measurementTime >>>>> {}", measurementTime);
                            break;

                        case "0420": // 2. Operating Time
                            log.info("Operating Time: {} {}", value, unit);

                            operatingTimeMeasurement.setType("C8y_Meter_Operating_Time");

                            MeasurementValue operatingTimeValue = new MeasurementValue();
                            operatingTimeValue.setValue(new BigDecimal(value));
                            operatingTimeValue.setUnit(unit);

                            Map<String, MeasurementValue> operatingTimeSeries = new HashMap<>();
                            operatingTimeSeries.put("Operating_Time", operatingTimeValue);

                            operatingTimeMeasurement.set(operatingTimeSeries, "Meter_Operating_Time");
                            log.info("operatingTimeMeasurement is >>>>> {}", operatingTimeMeasurement);
                            break;

                        case "0413": // 3. Volume
                            log.info("Volume: {} {}", value, unit);

                            volumeMeasurement.setType("C8y_Meter_Volume");

                            MeasurementValue volumeValue = new MeasurementValue();
                            volumeValue.setValue(new BigDecimal(value));
                            volumeValue.setUnit(unit);

                            Map<String, MeasurementValue> volumeSeries = new HashMap<>();
                            volumeSeries.put("V", volumeValue);

                            volumeMeasurement.set(volumeSeries, "Meter_Volume");
                            log.info("volumeMeasurement is >>>>> {}", volumeMeasurement);
                            break;

                        case "023B": // 4. Volume Flow
                            log.info("Volume Flow: {} {}", value, unit);

                            volumeFlowMeasurement.setType("C8y_Meter_Volume_Flow");
                            MeasurementValue volumeFlowValue = new MeasurementValue();
                            volumeFlowValue.setValue(new BigDecimal(value));
                            volumeFlowValue.setUnit(unit);

                            Map<String, MeasurementValue> volumeFlowSeries = new HashMap<>();
                            volumeFlowSeries.put("Flow", volumeFlowValue);

                            volumeFlowMeasurement.set(volumeFlowSeries, "Meter_Volume_Flow");
                            log.info("volumeFlowMeasurement is >>>>> {}", volumeFlowMeasurement);
                            break;

                        case "0259": // 5. Flow Temperature
                            log.info("Flow Temperature: {} {}", value, unit);

                            flowTemperatureMeasurement.setType("C8y_Meter_Flow_Temperature");
                            MeasurementValue flowTemperatureValue = new MeasurementValue();
                            flowTemperatureValue.setValue(new BigDecimal(value));
                            flowTemperatureValue.setUnit(unit);

                            Map<String, MeasurementValue> flowTemperatureSeries = new HashMap<>();
                            flowTemperatureSeries.put("T", flowTemperatureValue);

                            flowTemperatureMeasurement.set(flowTemperatureSeries, "Meter_Flow_Temperature");
                            log.info("flowTemperatureMeasurement is >>>>> {}", flowTemperatureMeasurement);
                            break;

                       case "01FD74": // 6. Remaining Battery
                            log.info("Remaining Battery: {} {}", value, unit);

                            remainingBatteryMeasurement.setType("C8y_Meter_Remaining_Battery");
                            MeasurementValue remainingBatteryValue = new MeasurementValue();
                            remainingBatteryValue.setValue(new BigDecimal(value));
                            remainingBatteryValue.setUnit(unit);

                            Map<String, MeasurementValue> remainingBatterySeries = new HashMap<>();
                            remainingBatterySeries.put("Remaining_Battery", remainingBatteryValue);

                            remainingBatteryMeasurement.set(remainingBatterySeries, "Meter_Remaining_Battery");
                            log.info("remainingBatteryMeasurement is >>>>> {}", remainingBatteryMeasurement);
                            break;
                    }
                } // end of for

                // create Measurments

                List<MeasurementRepresentation> list = Arrays.asList(
                        volumeMeasurement,
                        operatingTimeMeasurement,
                        volumeFlowMeasurement,
                        flowTemperatureMeasurement,
                       remainingBatteryMeasurement
                );
                MeasurementCollectionRepresentation collection = new MeasurementCollectionRepresentation();
                collection.setMeasurements(list);
                measurementApi.createBulk(collection);
                log.info("Measurements are created successfully .....");
            } else {
                log.info("drArray is not an array");
            }
        } catch (Exception e) {
            log.error("Cannot Parse wMbus Payload.");
            throw new DecoderServiceException(e, e.getMessage(), new DecoderResult());

        }
    }*/

   /* public static String dyecryptMeterPauload(String meterEncruptionKey, String meterEncryptedPayload) throws DecoderServiceException {

        byte[] meterEncruptionKeyBytes = hexStringToByteArray(meterEncruptionKey);
        byte[] meterEncryptedPayloadBytes = meterEncryptedPayload.getBytes();
        String meterDecryptedPayload = "";

        // 1. Build the 16-byte IV from the header parameters
        byte[] iv = new byte[16];
        // Manufacturer(2 bytes), Address(4 bytes), Version(1 byte), Type(1 byte)
        System.arraycopy(meterEncryptedPayloadBytes, 2, iv, 0, 8);

        // Access Number is at byte index 11 for Short Header (CI = 0x7A)
        byte accessNo = meterEncryptedPayloadBytes[11];
        for (int i = 8; i < 16; i++) {
            iv[i] = accessNo;                    // Repeat Access No across bytes 8..15
        }

        // 2. Determine Ciphertext Offset and Length
        int ciphertextOffset = 13; // Index where encrypted payload begins
        int rawCiphertextLen = meterEncryptedPayloadBytes.length - ciphertextOffset;

        // 3. FIX: Enforce block size alignment (truncate extra trailing RF/CRC bytes to multiple of 16)
        int validCiphertextLen = (rawCiphertextLen / 16) * 16;

        byte[] ciphertext = new byte[validCiphertextLen];
        System.arraycopy(meterEncryptedPayloadBytes, ciphertextOffset, ciphertext, 0, validCiphertextLen);

        // 4. Decrypt via AES-128-CBC
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(meterEncruptionKeyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            meterDecryptedPayload = Base64.getEncoder().encodeToString(cipher.doFinal(ciphertext));
        } catch (Exception e) {
            log.error("Cannot Decrypt Meter Payload.");
            throw new DecoderServiceException(e, e.getMessage(), new DecoderResult());
        }
        return meterDecryptedPayload;
    }*/

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // Helper method to construct Cumulocity Measurement Representations
    private MeasurementRepresentation createMeasurement(
            ManagedObjectRepresentation meterMO,
            String type,
            String seriesFragment,
            String seriesName,
            BigDecimal value,
            String unit,
            DateTime timestamp) {

        MeasurementRepresentation measurement = new MeasurementRepresentation();
        measurement.setSource(meterMO);
        measurement.setType(type);
        measurement.setDateTime(timestamp);

        MeasurementValue measurementValue = new MeasurementValue();
        measurementValue.setValue(value);
        measurementValue.setUnit(unit);

        Map<String, MeasurementValue> seriesMap = new HashMap<>();
        seriesMap.put(seriesName, measurementValue);

        measurement.set(seriesMap, seriesFragment);
        return measurement;
    }
}
