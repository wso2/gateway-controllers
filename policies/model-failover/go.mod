module github.com/wso2/gateway-controllers/policies/model-failover

go 1.26.2

// Pinned to v0.4.3 rather than the latest v0.5.1, deliberately: v0.4.3 is the version
// gateway-runtime/policy-engine itself requires, so it is the exact fault contract the engine
// implements, and matching it means this policy adds no minimum-version-selection lift to a
// gateway build — every other policy in the image keeps resolving the SDK it was written
// against. v0.4.2 is the floor (it introduced FaultPolicy); revisit when the engine moves.
require github.com/wso2/api-platform/sdk/core v0.4.3
