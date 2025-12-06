package decentralabs.blockchain.dto.intent;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("IntentAction Tests")
class IntentActionTest {

    @Nested
    @DisplayName("Enum Value Tests")
    class EnumValueTests {

        @Test
        @DisplayName("Should have LAB_ADD action")
        void shouldHaveLabAddAction() {
            assertNotNull(IntentAction.LAB_ADD);
            assertEquals(1, IntentAction.LAB_ADD.getId());
            assertEquals("LAB_ADD", IntentAction.LAB_ADD.getWireValue());
            assertFalse(IntentAction.LAB_ADD.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have LAB_ADD_AND_LIST action")
        void shouldHaveLabAddAndListAction() {
            assertNotNull(IntentAction.LAB_ADD_AND_LIST);
            assertEquals(2, IntentAction.LAB_ADD_AND_LIST.getId());
            assertEquals("LAB_ADD_AND_LIST", IntentAction.LAB_ADD_AND_LIST.getWireValue());
            assertFalse(IntentAction.LAB_ADD_AND_LIST.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have LAB_SET_URI action")
        void shouldHaveLabSetUriAction() {
            assertNotNull(IntentAction.LAB_SET_URI);
            assertEquals(3, IntentAction.LAB_SET_URI.getId());
            assertEquals("LAB_SET_URI", IntentAction.LAB_SET_URI.getWireValue());
            assertFalse(IntentAction.LAB_SET_URI.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have LAB_UPDATE action")
        void shouldHaveLabUpdateAction() {
            assertNotNull(IntentAction.LAB_UPDATE);
            assertEquals(4, IntentAction.LAB_UPDATE.getId());
            assertEquals("LAB_UPDATE", IntentAction.LAB_UPDATE.getWireValue());
            assertFalse(IntentAction.LAB_UPDATE.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have LAB_DELETE action")
        void shouldHaveLabDeleteAction() {
            assertNotNull(IntentAction.LAB_DELETE);
            assertEquals(5, IntentAction.LAB_DELETE.getId());
            assertEquals("LAB_DELETE", IntentAction.LAB_DELETE.getWireValue());
            assertFalse(IntentAction.LAB_DELETE.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have LAB_LIST action")
        void shouldHaveLabListAction() {
            assertNotNull(IntentAction.LAB_LIST);
            assertEquals(6, IntentAction.LAB_LIST.getId());
            assertEquals("LAB_LIST", IntentAction.LAB_LIST.getWireValue());
            assertFalse(IntentAction.LAB_LIST.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have LAB_UNLIST action")
        void shouldHaveLabUnlistAction() {
            assertNotNull(IntentAction.LAB_UNLIST);
            assertEquals(7, IntentAction.LAB_UNLIST.getId());
            assertEquals("LAB_UNLIST", IntentAction.LAB_UNLIST.getWireValue());
            assertFalse(IntentAction.LAB_UNLIST.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have RESERVATION_REQUEST action")
        void shouldHaveReservationRequestAction() {
            assertNotNull(IntentAction.RESERVATION_REQUEST);
            assertEquals(8, IntentAction.RESERVATION_REQUEST.getId());
            assertEquals("RESERVATION_REQUEST", IntentAction.RESERVATION_REQUEST.getWireValue());
            assertTrue(IntentAction.RESERVATION_REQUEST.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have CANCEL_RESERVATION_REQUEST action")
        void shouldHaveCancelReservationRequestAction() {
            assertNotNull(IntentAction.CANCEL_RESERVATION_REQUEST);
            assertEquals(9, IntentAction.CANCEL_RESERVATION_REQUEST.getId());
            assertEquals("CANCEL_RESERVATION_REQUEST", IntentAction.CANCEL_RESERVATION_REQUEST.getWireValue());
            assertTrue(IntentAction.CANCEL_RESERVATION_REQUEST.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have CANCEL_BOOKING action")
        void shouldHaveCancelBookingAction() {
            assertNotNull(IntentAction.CANCEL_BOOKING);
            assertEquals(10, IntentAction.CANCEL_BOOKING.getId());
            assertEquals("CANCEL_BOOKING", IntentAction.CANCEL_BOOKING.getWireValue());
            assertFalse(IntentAction.CANCEL_BOOKING.usesReservationPayload());
        }

        @Test
        @DisplayName("Should have REQUEST_FUNDS action")
        void shouldHaveRequestFundsAction() {
            assertNotNull(IntentAction.REQUEST_FUNDS);
            assertEquals(11, IntentAction.REQUEST_FUNDS.getId());
            assertEquals("REQUEST_FUNDS", IntentAction.REQUEST_FUNDS.getWireValue());
            assertFalse(IntentAction.REQUEST_FUNDS.usesReservationPayload());
        }
    }

    @Nested
    @DisplayName("fromId Tests")
    class FromIdTests {

        @Test
        @DisplayName("Should return LAB_ADD from id 1")
        void shouldReturnLabAddFromId() {
            Optional<IntentAction> result = IntentAction.fromId(1);
            assertTrue(result.isPresent());
            assertEquals(IntentAction.LAB_ADD, result.get());
        }

        @Test
        @DisplayName("Should return RESERVATION_REQUEST from id 8")
        void shouldReturnReservationRequestFromId() {
            Optional<IntentAction> result = IntentAction.fromId(8);
            assertTrue(result.isPresent());
            assertEquals(IntentAction.RESERVATION_REQUEST, result.get());
        }

        @Test
        @DisplayName("Should return REQUEST_FUNDS from id 11")
        void shouldReturnRequestFundsFromId() {
            Optional<IntentAction> result = IntentAction.fromId(11);
            assertTrue(result.isPresent());
            assertEquals(IntentAction.REQUEST_FUNDS, result.get());
        }

        @Test
        @DisplayName("Should return empty for invalid id")
        void shouldReturnEmptyForInvalidId() {
            Optional<IntentAction> result = IntentAction.fromId(999);
            assertFalse(result.isPresent());
        }

        @Test
        @DisplayName("Should return empty for null id")
        void shouldReturnEmptyForNullId() {
            Optional<IntentAction> result = IntentAction.fromId(null);
            assertFalse(result.isPresent());
        }

        @Test
        @DisplayName("Should return empty for zero id")
        void shouldReturnEmptyForZeroId() {
            Optional<IntentAction> result = IntentAction.fromId(0);
            assertFalse(result.isPresent());
        }
    }

    @Nested
    @DisplayName("fromWireValue Tests")
    class FromWireValueTests {

        @Test
        @DisplayName("Should return LAB_ADD from wire value")
        void shouldReturnLabAddFromWireValue() {
            Optional<IntentAction> result = IntentAction.fromWireValue("LAB_ADD");
            assertTrue(result.isPresent());
            assertEquals(IntentAction.LAB_ADD, result.get());
        }

        @Test
        @DisplayName("Should return RESERVATION_REQUEST from wire value")
        void shouldReturnReservationRequestFromWireValue() {
            Optional<IntentAction> result = IntentAction.fromWireValue("RESERVATION_REQUEST");
            assertTrue(result.isPresent());
            assertEquals(IntentAction.RESERVATION_REQUEST, result.get());
        }

        @Test
        @DisplayName("Should be case insensitive")
        void shouldBeCaseInsensitive() {
            Optional<IntentAction> result = IntentAction.fromWireValue("lab_add");
            assertTrue(result.isPresent());
            assertEquals(IntentAction.LAB_ADD, result.get());
        }

        @Test
        @DisplayName("Should handle whitespace")
        void shouldHandleWhitespace() {
            Optional<IntentAction> result = IntentAction.fromWireValue("  LAB_ADD  ");
            assertTrue(result.isPresent());
            assertEquals(IntentAction.LAB_ADD, result.get());
        }

        @Test
        @DisplayName("Should return empty for invalid wire value")
        void shouldReturnEmptyForInvalidWireValue() {
            Optional<IntentAction> result = IntentAction.fromWireValue("INVALID_ACTION");
            assertFalse(result.isPresent());
        }

        @Test
        @DisplayName("Should return empty for null wire value")
        void shouldReturnEmptyForNullWireValue() {
            Optional<IntentAction> result = IntentAction.fromWireValue(null);
            assertFalse(result.isPresent());
        }

        @Test
        @DisplayName("Should return empty for blank wire value")
        void shouldReturnEmptyForBlankWireValue() {
            Optional<IntentAction> result = IntentAction.fromWireValue("   ");
            assertFalse(result.isPresent());
        }

        @Test
        @DisplayName("Should return empty for empty wire value")
        void shouldReturnEmptyForEmptyWireValue() {
            Optional<IntentAction> result = IntentAction.fromWireValue("");
            assertFalse(result.isPresent());
        }
    }

    @Nested
    @DisplayName("values Tests")
    class ValuesTests {

        @Test
        @DisplayName("Should return all values")
        void shouldReturnAllValues() {
            IntentAction[] values = IntentAction.values();
            assertEquals(11, values.length);
        }

        @Test
        @DisplayName("Should contain all expected actions")
        void shouldContainAllExpectedActions() {
            IntentAction[] values = IntentAction.values();
            
            assertTrue(containsAction(values, IntentAction.LAB_ADD));
            assertTrue(containsAction(values, IntentAction.LAB_ADD_AND_LIST));
            assertTrue(containsAction(values, IntentAction.LAB_SET_URI));
            assertTrue(containsAction(values, IntentAction.LAB_UPDATE));
            assertTrue(containsAction(values, IntentAction.LAB_DELETE));
            assertTrue(containsAction(values, IntentAction.LAB_LIST));
            assertTrue(containsAction(values, IntentAction.LAB_UNLIST));
            assertTrue(containsAction(values, IntentAction.RESERVATION_REQUEST));
            assertTrue(containsAction(values, IntentAction.CANCEL_RESERVATION_REQUEST));
            assertTrue(containsAction(values, IntentAction.CANCEL_BOOKING));
            assertTrue(containsAction(values, IntentAction.REQUEST_FUNDS));
        }

        @Test
        @DisplayName("Should have unique ids")
        void shouldHaveUniqueIds() {
            IntentAction[] values = IntentAction.values();
            java.util.Set<Integer> ids = new java.util.HashSet<>();
            
            for (IntentAction action : values) {
                assertTrue(ids.add(action.getId()), 
                    "Duplicate id found: " + action.getId() + " for " + action.name());
            }
        }

        private boolean containsAction(IntentAction[] values, IntentAction action) {
            for (IntentAction a : values) {
                if (a == action) return true;
            }
            return false;
        }
    }

    @Nested
    @DisplayName("Reservation Payload Tests")
    class ReservationPayloadTests {

        @Test
        @DisplayName("Only RESERVATION_REQUEST and CANCEL_RESERVATION_REQUEST use reservation payload")
        void onlyReservationActionsUseReservationPayload() {
            int reservationPayloadCount = 0;
            for (IntentAction action : IntentAction.values()) {
                if (action.usesReservationPayload()) {
                    reservationPayloadCount++;
                    assertTrue(action == IntentAction.RESERVATION_REQUEST || 
                              action == IntentAction.CANCEL_RESERVATION_REQUEST,
                        "Unexpected action using reservation payload: " + action.name());
                }
            }
            assertEquals(2, reservationPayloadCount);
        }
    }
}
