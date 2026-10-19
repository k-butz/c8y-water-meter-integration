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

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OMSDecoderC8YParserServiceTest {


    private final IdentityApi identityApi = mock(IdentityApi.class);
    private final InventoryApi inventoryApi = mock(InventoryApi.class);
    private final MeasurementApi measurementApi = mock(MeasurementApi.class);
    private final HttpClient httpClient = mock(HttpClient.class);

    private OMSDecoderC8YParserService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        ContextService<MicroserviceCredentials> contextService = mock(ContextService.class);
        when(contextService.getContext()).thenReturn(mock(MicroserviceCredentials.class));

        service = new OMSDecoderC8YParserService(null, contextService, httpClient, "http://c8y.test");
        service.identityApi = identityApi;
        service.inventoryApi = inventoryApi;
        service.measurementApi = measurementApi;
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
}
