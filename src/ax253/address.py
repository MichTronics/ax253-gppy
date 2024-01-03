"""AX.25 address encode/decode"""
import re
from typing import Any, Union

import attr.validators
from attrs import define, field
from attr import validators
from bitarray import bitarray


__author__ = "Masen Furer KF7HVM <kf7hvm@0x26.net>"
__copyright__ = "Copyright 2022 Masen Furer and Contributors"
__license__ = "Apache License, Version 2.0"


VALID_CALLSIGN_REX = re.compile(rb"^[A-Z0-9]+$")


def valid_callsign(instance, attribute, value):
    validators.instance_of(bytes)(instance, attribute, value)
    if not VALID_CALLSIGN_REX.match(value):
        raise ValueError("{!r} does not match {!r}".format(value, VALID_CALLSIGN_REX))


@define(slots=True, frozen=True)
class Address:
    """A source, destination, or path entry in an AX.25 frame."""

    callsign: bytes = field(converter=lambda c: c.upper(), validator=valid_callsign)
    """The callsign associated with the address."""
    ssid: int = field(default=0, converter=int)
    """The ssid (0-15) extension of the callsign."""
    digi: bool = field(default=False, converter=bool)
    """If true, indicates that this address has digipeated the packet."""
    # The high order bit of HLDC; True indicates end of address information.
    a7_hldc: bool = field(default=True, converter=bool, repr=False)

    ##### New code for changing the C-Bit in the SSID byte ######
    #   Frame Type          Dest. SSID C-Bit    Source SSID C-Bit
    #
    #  Previous versions             0                    0
    #  Command (V.2.0)               1                    0
    #  Response (V.2.0)              0                    1
    #  Previous versions             1                    1
    ##############################################################
    """If true it set the C-Bit to be a command."""
    a0_dcr: bool = field(default=False, converter=bool, repr=False)
    """If true it set the C-Bit to be a response."""
    a0_scr: bool = field(default=False, converter=bool, repr=False)

    @classmethod
    def from_bytes(cls, ax25_address: bytes, **kwargs: Any) -> "Address":
        """Create an address from ax25 bytes."""
        if len(ax25_address) != 7:
            raise ValueError(
                "ax25 address must be 7 bytes, got {}".format(len(ax25_address))
            )
        callsign = bytes(b >> 1 for b in ax25_address[:6]).rstrip()
        ssid = (ax25_address[6] >> 1) & 0x0F
        a7 = bitarray()
        a7.frombytes(ax25_address[6:7])
        c_or_h = a7[0]
        r = a7[1:3]  # noqa: F841
        hldc = a7[7]
        init_kwargs = dict(
            callsign=callsign,
            ssid=ssid,
            digi=c_or_h if hldc else False,
            a7_hldc=hldc,
        )
        if kwargs:
            init_kwargs.update(kwargs)
        return cls(**init_kwargs)

    @classmethod
    def from_str(
        cls, address_spec: str, a7_hldc: bool = False, dcr: bool = None, scr: bool = None, **kwargs: Any,
    ) -> "Address":
        """Create an address from a string (TNC2 format)."""
        digi = "*" in address_spec
        address = address_spec.strip("*")
        callsign_str, found, ssid_str = address.partition("-")
        callsign = callsign_str.encode("utf-8")

        ssid = int(ssid_str) if ssid_str else 0
        init_kwargs = dict(
            callsign=callsign,
            ssid=ssid,
            digi=digi,
            a7_hldc=digi or a7_hldc,
            # Add this for setting the c bit in the SSID byte.
            a0_dcr=dcr,
            a0_scr=scr,
        )
        if kwargs:
            init_kwargs.update(**kwargs)
        return cls(**init_kwargs)

    @classmethod
    def from_any(
        cls, address: Union["Address", bytes, str], **kwargs: Any,
    ) -> "Address":
        """Create an address from any supported value."""
        if isinstance(address, cls):
            if kwargs:
                address = address.evolve(**kwargs)
            return address
        elif isinstance(address, bytes):
            return cls.from_bytes(address, **kwargs)
        return cls.from_str(str(address), **kwargs)

    def __str__(self) -> str:
        """Encode address as TNC2 string."""
        return "".join(
            [
                self.callsign.decode("latin1"),
                # Append SSID if non-zero
                "-%d" % self.ssid if self.ssid else "",
                # If callsign was digipeated, append '*'.
                "*" if self.digi else "",
            ]
        )

    def __bytes__(self) -> bytes:
        """Encode address as ax25 bytes."""
        if len(self.callsign) > 6:
            raise ValueError(
                "Cannot encode callsign > 6 bytes: {}".format(self.callsign)
            )
        callsign = bytes(b << 1 for b in self.callsign.ljust(6))
        a7 = bitarray()
        a7.frombytes(bytes([self.ssid << 1]))
        ### Change the code for setting the C bit in the SSID byte.
        a7[0] = self.digi and self.a0_dcr or self.a0_scr
        a7[1:3] = True  # r
        a7[7] = self.a7_hldc 
        return callsign + a7.tobytes()

    def evolve(self, **kwargs) -> "Address":
        """Create a new Address by applying kwargs to this Address."""
        return attr.evolve(self, **kwargs)
