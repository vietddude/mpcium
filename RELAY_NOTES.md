# Relay Notes

## What The Current Relay Does

The current relay is a thin transport and presence layer for cosigners. It is not an MPC runtime.

It currently does the following:

1. Accepts MQTT connections from cosigners.
2. Authenticates cosigners using static username/password credentials from config.
3. Maps MQTT topics to NATS subjects and back.
4. Forwards outbound messages from NATS to MQTT for online cosigners.
5. Forwards inbound messages from MQTT back to NATS with cosigner metadata.
6. Tracks cosigner presence in Redis.
7. Publishes presence events to NATS.
8. Enforces one active session per cosigner, where a new connection takes over the old one.

## What The Current Relay Does Not Do

The current relay does not:

1. Run MPC rounds.
2. Create keygen or signing sessions.
3. Persist MPC shares.
4. Coordinate threshold logic.
5. Replace `mpc.Node`.
6. Wrap MPC sessions with `mpcium-sdk/secure`.

In short, the current relay is only a message transport and presence service for cosigners.

## Main Code Areas

Entrypoint:

- `cmd/mpcium-relay/main.go`

Core runtime:

- `pkg/relay/runtime.go`

Topic mapping:

- `pkg/relay/topics.go`

MQTT hook:

- `pkg/relay/mqtt_hook.go`

Presence:

- `pkg/relay/presence.go`

Session registry:

- `pkg/relay/sessions.go`

Config:

- `pkg/config/relay.go`

## Subject And Topic Layout

NATS outbound to cosigner:

- `mpc.relay.to_cosigner.<cosigner_id>.<wallet_id>.<tail...>`

NATS inbound from cosigner:

- `mpc.relay.from_cosigner.<cosigner_id>.<wallet_id>.<tail...>`

Presence events:

- `mpc.relay.cosigner.status.<cosigner_id>`

MQTT namespace:

- `cosigner/<cosigner_id>/<wallet_id>/<tail...>`

## Conclusion

If the goal is to make a node run MPC through a relay-backed cosigner flow using `mpcium-sdk` secure sessions, then an additional runtime or session layer is still needed on the participant or cosigner side. The current relay can be reused as the transport layer, but it does not run MPC by itself.
