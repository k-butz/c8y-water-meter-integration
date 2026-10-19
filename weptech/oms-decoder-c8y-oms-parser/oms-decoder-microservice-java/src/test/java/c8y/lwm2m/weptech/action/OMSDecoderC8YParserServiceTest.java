package c8y.lwm2m.weptech.action;

import com.cumulocity.microservice.context.ContextService;
import com.cumulocity.microservice.context.credentials.MicroserviceCredentials;
import com.cumulocity.microservice.customdecoders.api.exception.DecoderServiceException;
import com.cumulocity.model.ID;
import com.cumulocity.model.idtype.GId;
import com.cumulocity.rest.representation.identity.ExternalIDRepresentation;
import com.cumulocity.rest.representation.inventory.ManagedObjectRepresentation;
import com.cumulocity.sdk.client.identity.IdentityApi;
import com.cumulocity.sdk.client.inventory.InventoryApi;
import com.cumulocity.sdk.client.measurement.MeasurementApi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OMSDecoderC8YParserServiceTest {

    private static final String KEY = "00112233445566778899AABBCCDDEEFF";
    private static final String EMPTY_RESULT = "{\"status\":\"success\",\"data\":{\"parsed_measurements\":[]}}";

    private final IdentityApi identityApi = mock(IdentityApi.class);
    private final InventoryApi inventoryApi = mock(InventoryApi.class);
    private final MeasurementApi measurementApi = mock(MeasurementApi.class);
    private final HttpClient httpClient = mock(HttpClient.class);

    @SuppressWarnings("unchecked")
    private final ContextService<MicroserviceCredentials> contextService = mock(ContextService.class);

    private OMSDecoderC8YParserService service;

    @BeforeEach
    void setUp() {
        when(contextService.getContext()).thenReturn(mock(MicroserviceCredentials.class));

        service = newService(httpClient, "http://c8y.test");
    }

    private OMSDecoderC8YParserService newService(HttpClient client, String baseUrl) {
        OMSDecoderC8YParserService s = new OMSDecoderC8YParserService(null, contextService, client, baseUrl);
        s.identityApi = identityApi;
        s.inventoryApi = inventoryApi;
        s.measurementApi = measurementApi;
        return s;
    }

    private static String hex(String gatewayCsv) {
        return HexFormat.of().formatHex(gatewayCsv.getBytes(StandardCharsets.US_ASCII));
    }

    private void meter(Object omsMode, String key) {
        ManagedObjectRepresentation mo = new ManagedObjectRepresentation();
        mo.setId(GId.asGId("42"));
        mo.set(omsMode, "oms_mode");
        if (key != null) {
            mo.set(key, "meter_encryption_key");
        }

        ExternalIDRepresentation externalId = new ExternalIDRepresentation();
        externalId.setManagedObject(mo);
        when(identityApi.getExternalId(any(ID.class))).thenReturn(externalId);
        when(inventoryApi.get(any(GId.class))).thenReturn(mo);
    }

    @SuppressWarnings("unchecked")
    private void parserResponds(int status, String body) throws Exception {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        doReturn(response).when(httpClient).send(any(HttpRequest.class), any());
    }

    private String decodeValidTelegram() throws DecoderServiceException {
        service.decode(hex("0,1,2,3,4,5,6,SERIAL1,YUQJBw=="), GId.asGId("1"), null);
        return "ok";
    }

    @Test
    void gatewayRecordWithEightFieldsIsRejectedWithoutIndexError() {
        assertDoesNotThrow(() -> service.decode(hex("0,1,2,3,4,5,6,7"), GId.asGId("1"), null));
        verifyNoInteractions(identityApi, httpClient);
    }

    @Test
    void emptyGatewayPayloadIsRejectedWithoutIndexError() {
        assertDoesNotThrow(() -> service.decode("", GId.asGId("1"), null));
        verifyNoInteractions(identityApi, httpClient);
    }

    @Test
    void omsModeStoredAsStringIsAccepted() throws Exception {
        meter("5", null);
        parserResponds(200, EMPTY_RESULT);

        assertDoesNotThrow(this::decodeValidTelegram);
        verify(httpClient).send(any(HttpRequest.class), any());
    }

    @Test
    void omsModeStoredAsIntegerIsAccepted() throws Exception {
        meter(5, null);
        parserResponds(200, EMPTY_RESULT);

        assertDoesNotThrow(this::decodeValidTelegram);
        verify(httpClient).send(any(HttpRequest.class), any());
    }

    @Test
    void parserErrorMessageIsPropagated() throws Exception {
        meter(7L, KEY);
        parserResponds(422, "{\"status\":\"error\",\"error\":\"Decryption failed: wrong key\"}");

        DecoderServiceException e = assertThrows(DecoderServiceException.class, this::decodeValidTelegram);
        assertTrue(e.getMessage().contains("Decryption failed: wrong key"), e.getMessage());
    }

    @Test
    void noMeasurementsAreSentWhenNoRecordMatches() throws Exception {
        meter(5L, null);
        parserResponds(200, EMPTY_RESULT);

        decodeValidTelegram();

        verify(measurementApi, never()).createBulk(any());
    }

    @Test
    void matchingRecordIsSent() throws Exception {
        meter(5L, null);
        parserResponds(200, "{\"status\":\"success\",\"data\":{\"parsed_measurements\":["
                + "{\"header_raw\":\"0413\",\"value\":\"10\",\"unit\":\"m³\"}]}}");

        decodeValidTelegram();

        verify(measurementApi).createBulk(any());
    }

    @Test
    void hangingParserCallTimesOut() throws Exception {
        meter(5L, null);
        HttpServer parser = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        parser.createContext("/", exchange -> {
            try {
                Thread.sleep(3000);
            } catch (InterruptedException ignored) {
            }
            byte[] body = EMPTY_RESULT.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        parser.start();
        try {
            service = newService(HttpClient.newHttpClient(), "http://127.0.0.1:" + parser.getAddress().getPort());
            service.parserRequestTimeout = Duration.ofMillis(500);

            assertTimeoutPreemptively(Duration.ofSeconds(2),
                    () -> assertThrows(DecoderServiceException.class, this::decodeValidTelegram));
        } finally {
            parser.stop(0);
        }
    }
}
