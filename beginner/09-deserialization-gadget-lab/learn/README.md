# Learn — deserialization gadgets

## What a gadget is

Some serialization formats can encode not just data but instructions to construct objects. A *gadget* is a class already present in the process whose construction or reduction has a side effect. Chaining gadgets can turn deserialization into code execution.

## Why pickle is dangerous

`pickle.loads` resolves every global named in the stream. If a stream says "call function X with argument Y", pickle will do it. That is fine for data you produced yourself and catastrophic for data from an attacker.

## The defence: allowlist globals

`pickle.Unpickler.find_class` is called for every global reference. Overriding it to permit only known modules turns arbitrary code execution into a clean rejection. Plain lists, dicts, and strings still load normally.

## Better still

Do not deserialize untrusted data with pickle at all. Use JSON, msgpack, or a schema-driven format. If you must use pickle, sign the data with an HMAC and verify before loading.
