# Learn — nginx-style access control

## Directive order

Nginx access rules are processed in the order they appear. The first matching `allow` or `deny` decides the request, so a broad rule placed before a specific one can shadow it. Rule order is part of the policy.

## Match dimensions

Real edge rules commonly combine a URI prefix, an HTTP method, a client subnet, and sometimes a header value. Combining dimensions lets an operator allow a public read path while restricting a write endpoint to an internal network with an extra header.

## CIDR notation

A CIDR block such as `10.0.0.0/8` describes a range of addresses compactly. Checking membership is preferable to string prefix comparisons, which can match unrelated addresses.

## Default behaviour

Nginx allows a request when no access directive matches. This teaching engine defaults to deny, which is a safer posture for an evaluator and makes the absence of a rule explicit in the output.

## Why simulate

Evaluating synthetic requests against data files is deterministic and safe. It teaches control-flow and ordering without configuring a server, binding a port, or exposing a service.
