BEGIN;

-- Operator redelivery reserves one attempt against the original immutable event.
-- Separate append-only request/outcome rows preserve unfinished/crashed actions.
CREATE TABLE judge.callback_redelivery_requests (
 replay_id uuid PRIMARY KEY,
 event_id uuid NOT NULL REFERENCES judge.callback_outbox(event_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
 lease_token uuid NOT NULL UNIQUE,
 operator_ref text NOT NULL CHECK (length(operator_ref) BETWEEN 1 AND 128 AND operator_ref ~ '^[A-Za-z0-9_.@-]+$'),
 reason text NOT NULL CHECK (reason IN ('MAPPING_RECONCILED','AUTH_RESTORED','TRANSPORT_RESTORED','CONFLICT_RESOLVED')),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(event_id,lease_token)
);
CREATE INDEX callback_redelivery_event ON judge.callback_redelivery_requests(event_id,created_at);

CREATE TABLE judge.callback_redelivery_outcomes (
 replay_id uuid PRIMARY KEY REFERENCES judge.callback_redelivery_requests(replay_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
 status text NOT NULL CHECK (status IN ('DELIVERED','FAILED','INTERRUPTED')),
 last_error_code text CHECK (last_error_code IN ('CALLBACK_UNAUTHORIZED','CALLBACK_TASK_NOT_FOUND','CALLBACK_EVENT_CONFLICT','CALLBACK_INVALID_ARGUMENT','CALLBACK_UNAVAILABLE','CALLBACK_INVALID_ACK','CALLBACK_REJECTED','CALLBACK_HTTP_UNEXPECTED','CALLBACK_INTEGRITY_FAILURE','CALLBACK_LEASE_EXPIRED','CALLBACK_WINDOW_EXPIRED')),
 duplicate boolean NOT NULL DEFAULT false,
 finished_at timestamptz NOT NULL DEFAULT now(),
 CHECK ((status='DELIVERED' AND last_error_code IS NULL) OR (status<>'DELIVERED' AND last_error_code IS NOT NULL AND NOT duplicate)),
 CHECK (status<>'INTERRUPTED' OR last_error_code='CALLBACK_LEASE_EXPIRED')
);

CREATE TRIGGER immutable_callback_redelivery_requests BEFORE UPDATE OR DELETE ON judge.callback_redelivery_requests
 FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_callback_redelivery_outcomes BEFORE UPDATE OR DELETE ON judge.callback_redelivery_outcomes
 FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();

CREATE FUNCTION judge.check_callback_redelivery_request() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM judge.callback_outbox o WHERE o.event_id=NEW.event_id
 AND o.status='SENDING' AND o.lease_owner=NEW.lease_token AND o.lease_expires_at>clock_timestamp()
 AND o.created_at+interval '24 hours'<=NEW.created_at) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='redelivery requires an expired event and matching live lease';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_callback_redelivery_request AFTER INSERT ON judge.callback_redelivery_requests
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_callback_redelivery_request();

CREATE FUNCTION judge.check_callback_redelivery_outcome() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM judge.callback_redelivery_requests r JOIN judge.callback_outbox o ON o.event_id=r.event_id
 WHERE r.replay_id=NEW.replay_id AND r.created_at<=NEW.finished_at
 AND ((NEW.status='DELIVERED' AND o.status='DELIVERED') OR (NEW.status<>'DELIVERED' AND o.status='DEAD_LETTER'))) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='redelivery outcome and retained event mismatch';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_callback_redelivery_outcome AFTER INSERT ON judge.callback_redelivery_outcomes
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_callback_redelivery_outcome();

COMMIT;
