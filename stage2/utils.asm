.global payloadbin
.type   payloadbin, @object
.align  4

payloadbin:
    .incbin "payload.bin"
payloadbinend:
    .global payloadbin_size
    .type   payloadbin_size, @object
    .align  4
payloadbin_size:
    .int    payloadbinend - payloadbin