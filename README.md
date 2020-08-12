# Azure Sphere Internals - Overview
Written by [Matt Suiche](https://twitter.com/msuiche/) and [Nikita Karetnikov](https://twitter.com/karetnikovn/).

## Introduction

In May, Microsoft announced a bounty for their new IoT platform called Azure
Sphere.  The interesting part about it is that it's created with security in
mind, which is a much needed initiative, so we decided to take a look.

While we didn't find any issues worth reporting, we thought it would be a waste
not to share what we've learned.  Hopefully, this will be useful for others
wanting to research the platform or those considering to use it for their
projects.

## The Bounty

The [bounty] was set up as a limited-time and invite-only challenge.  In order
to even be eligible for a potential [payout], you had to be selected among
around 3000 applicants.  And only around 80 were accepted in the end.

As an aside, it's not clear to us why limited-time and invite-only programs are
a thing.  In general, this and the bounty model itself only benefits companies
while researchers are clearly getting the bad side of the deal.  This needs to
change as no one should work for free.

That said, when the bounty was announced, other companies were panicking due to
COVID-19, firing people left and right, so it looked like a good gamble at the
time.

Later we learned that Microsoft also hired a few security firms to audit the
platform while the bounty was still ongoing.  This is on top of fuzzing and red
team engagements they do internally.

Our team got accepted and had to sign some document and send it to Microsoft.
In return, Microsoft sent us a seeed [dev board] and scheduled the office hours
throughout the summer on Slack.

There is nothing special about this dev board, by the way, it doesn't provide
any special debugging capabilities.  It's the same board you could buy yourself,
which we did before the program even started.

The office hours were meant for discussing the program rules.  No additional
information was provided, the program assumed an external attacker.

According to the [payout] page, any issues besides Critical and Important will
get you $0 USD.  DoS is out of scope too.  Because of this, we focused on the
most privileged components from the start, but more on this later.

The following sections are not in the chronological order.  Instead, the content
is grouped into categories.

## Dev Kits

Besides the board that Microsoft sent us, we ordered several seeed and Avnet
kits.  You always want to have spares in case things break and there might be
issues with a particular kit, so it's better to have options.

The Avnet kit is slightly nicer for research purposes because some of the test
points are marked on the board and there are headers that provide 3.3v, 5v, and
ground, which is great for testing.  Also, the Azure Sphere mt3620 chip is
mounted on a separate board (called the module), which is soldered on top of the
main one.  The module only exposes 64 pins while the mt3620 chip itself has 164.

Some of the module pins:

| PIN          | Value |
|--------------|-------|
| IO1_TXD      | 61    |
| IO0_TXD      | 60    |
| RECOVERY_CTS | 59    |
| RECOVERY_RTS | 58    |
| RECOVERY_TXD | 57    |
| RECOVERY_RXD | 56    |
|--------------|-------|
| SERVICE_CTS  | 55    |
| SERVICE_RTS  | 54    |
| SERVICE_RXD  | 53    |
| SERVICE_TXD  | 52    |
|--------------|-------|
| SYSRST_N     | 55    |
| SWO          | 54    |
| SWD_CLK      | 53    |
| SWD_DIO      | 52    |
|--------------|-------|
| DEBUG_CTS    | 47    |
| DEBUG_TXD    | 46    |
| DEBUG_RTS    | 45    |
| DEBUG_RXD    | 44    |

See page 13 in the [Avnet AES-MS-MT3620-M-G Module Data Sheet and User Manual].

Using a multimeter in the continuity mode, we probed the module pins to find the
test points on the board for recovery, service, and debug interfaces as well as
SWD.  Then we soldered wires to them.

## SWD and UARTs

SWD is used for hardware debugging on the Cortex-M4 cores.  One M4 core is
reserved for user applications and the other for the Pluton security subsystem.
Naturally, we wanted to see if we can debug Pluton this way.  That didn't work
because the access seems to be restricted via [ARM security features].  To
verify our setup, we [enabled debugging] on the user M4 core and debugged it
with OpenOCD and Bus Blaster.  Note that we had to use the provided OpenOCD
because it has a patch for working with SWD.  As far as we know, there are no
other changes to it that would interfere with debugging Pluton, but you can
always build it yourself to be sure.  Also, Bus Blaster needs to be flashed
with the KT-link buffer to be able to debug via SWD.

As for the UART interfaces, this is mostly useful if you want to sniff the port
while it's being used by the OS, or if you want to avoid powering the board over
USB.

There is also some confusion when it comes to the naming of these UARTs, so
we'll just say that one of them is used for platform debug output and
interacting with the recovery mode.   For debugging, the common settings are
used:

| Name         | Value   |
|--------------|---------|
| Baud rate    | 115200  |
| Data bits    | 8       |
| Stop bits    | 1       |
| Parity       | none    |
| Flow control | none    |
| Forward      | none    |

(The recovery case will be covered separately.)

The second UART is used by the SDK to communicate with the device and you won't
be able to open it unless you solder some wires to the pins directly.
Decompiled from the SDK, its settings are:

```cpp
uart.Open(new SerialPortConfiguration()
{
    BaudRate = 921600,
    Parity = DeviceControl.Common.Parity.None,
    DataBits = 8,
    StopBits = DeviceControl.Common.StopBits.One,
    Handshake = DeviceControl.Common.Handshake.RequestToSend
});
```

See the DLLs in `C:\Program Files (x86)\Azure Sphere Device Communication Service`.

The packets are sent to the [TUN/TAP] interface in the OS over HTTPS, which is
encapsulated using [SLIP].  Since it's HTTPS, you won't be able to see anything
even if you solder wires to these pins.  On the device, there seems to be a
pinned certificate, so you cannot MITM the connection either.  The best you can
do is to attach a C#-aware debugger to the SDK/service running on the OS or use
dynamic instrumentation.

The third UART interface seems to be unused.

## mt3620 JTAG and Trace Ports

There are also interesting pins on the mt3620 chip itself.  Search the [MT3620
Datasheet] for "CA7 Jtag" and "N9 JTAG".  The former is the high-level
Cortex-A7 processor, the latter is the Wi-Fi chip.  There are also trace ports.

Some of the mt3620 pins:

| PIN          | JTAG     | /         |
|--------------|----------|-----------|
| GPIO19       | CA7 JTAG | CA7_NTRST |
| GPIO22        | CA7 JTAG  | CA7_TDI    |
| GPIO23        | CA7 JTAG  | CA7_TDO    |
|-|-|-|
| GPIO4         | N9 JTAG  | MCU_JTCK    |
| GPIO5         | N9 JTAG  | MCU_JTMS    |
| GPIO6         | N9 JTAG  | MCU_JTDI    |
| GPIO7         | N9 JTAG  | MCU_JTRST_B |
| GPIO8         | N9 JTAG  | MCU_DBGIN   |
| GPIO10        | N9 JTAG  | MCU_DBGACKN |
| GPIO11        | N9 JTAG  | MCU_JTDO    |
| WF_ANTSEL0    | N9 JTAG  | MCU_DBGACKN |
| WF_ANTSEL1    | N9 JTAG  | MCU_JTDO    |

It's not clear to us why the N9 chip has so many pins while the A7 has only 3.

Our plan here was to find a way to communicate with these pins and then use
[JTAGulator] to brute-force and verify the pinout.  But this proved to be
difficult.

If you scroll to page 51 in the above datasheet, you'll see the physical
dimensions of the chip.  The top part has all the pins exposed via test points
around the edges of the chip, but you need a microscope (x20 zoom will do) and
a needle to probe them.  That is, you need to connect a needle to your multimeter
with alligator clips because the standard probes are too thick.

As far as we can tell, these pins have no test points on the board itself,
which is confirmed by the fact that the Avnet board doesn't expose them on
the module.

So you need to interface directly with the pins on the chip.  It seems there
exist very tiny pogo pins (0.2 mm, but it might be too thick anyway), which we
could try attaching to the module, but we couldn't get those locally and time
was an issue.  For the same reason, we didn't try creating an adapter using
specialized equipment, but it might be possible.

Because the pins are spaced wider and have bigger pads on the other side, we
also tried desoldering the chip with the intention to solder wires directly to
these pads and connecting everything using breadboards, which would allow us to
use standard jumper wires to sniff or cut out the connections to the pins.

## Removing the Chip

For desoldering, we are aware of two techniques.  You can use [low temperature
solder], but this didn't work at all in this case because the pins are too
tiny, it's just hard to make a connection.  Also, it might be impossible to
warm up the second row of the pads and the center of the chip might be
soldered too.  So you'll end up with a mess of solder on the board because it
flows so easily.

The second technique is to use a [hot air gun], which we managed to do (at around
380 degrees Celsius).  This is pretty easy.  The only problems with this
approach is that you may desolder nearby components by accident or damage the
chip itself due to high temperature.  So it's better to avoid using tweezers to
lift up the chip because it's hard to make a good grip.  Maybe using [Blu Tack]
attached to a screwdriver would work better, but we didn't try this.  It's also
unknown how Blu Tack would behave under high temperature and whether it
produces any dangerous fumes.

After removing the chip, we tried soldering a 30 AWG (0.25 mm) wire to the pins
on the bottom using a microscope, but it didn't work well.  This wire was round
and too thick.  To make a good connection, we had to apply quite a bit of
solder, which caused problems with the nearby pins.  We either created shorts
or desoldered the neighbors.  Since we couldn't get a smaller wire in time, we
gave up on this as well, but it's something that can be explored in the future.

## JTAG Adapter

Instead of soldering individual wires ourselves and using breadboards, we
thought about creating a surface-mounted adapter PCB that would allow
connecting the desoldered chip and the board and exposed the headers with pins
for jumper wires.  We thought about exposing three pins for each chip pin such
that we could connect and disconnect the two of them using a jumper and use the
other one for sniffing.

The adapter PCB looked promising at first, but there are a few problems with
this approach too.  The only realistic design we could think of would consist
of two standard PCBs connected via a flexible one, which would serve as a bus
for all the pins.  You can't just use a single standard PCB because the jumper
headers would take too much space and there are other components on the
original board that you need to not cover.  Instead, the first tiny PCB would
be soldered in place of the original chip, then the flexible PCB would connect
it to the PCB with the headers and the desoldered chip, to be placed
somewhere next to the original dev board.  In order to route the wires to use
a single bus like this, the PCBs need to be multi-layered too.

While there were fast local options for printing PCBs (hours), this approach
was abandoned due to the time required to design the PCBs, to select the materials,
and to test the whole scheme.  While using the hot air gun, we also
desoldered a bunch of tiny capacitors and resistors next to the chip, so this
would also need to be fixed and tested before making the whole thing work.
Ordering more dev boards wasn't an option due to time constraints.

## Strapping

Going back to JTAG, there's a set of strapping pins that look relevant.  Page
11 in the [Avnet AES-MS-MT3620-M-G Module Data Sheet and User Manual] is where
this is documented best.

| Function         | Pin Name     | Strapping | Recommendation                                 |
|------------------|--------------|-----------|------------------------------------------------|
| Normal/Test Mode | DEBUG_TXD    | Pull-Down | Pull-Down resistor is on module. Mode = Normal |
| Recovery mode    | DEBUG_RTS    | Pull-Down | Pull-down resistor required on OEM board! Controlled via PC interface, if present |
| RTC mode         | RECOVERY_TXD | Pull-Up   | Pull-up resistor is on module. RTC oscillator = 32 kHz crystal |
| 26MHz            | IO0_RTS      | Pull-Up | MT3620 internal pull-up on module. Oscillator frequency = 26 MHz |
| 26MHz            | IO0_TXD      | Pull-Down | Pull-down resistor is on module. Oscillator frequency = 26 MHz |
| N9 JTAG          | IO1_TXD | Pull-Down | Pull-down resistor is on module. N9 JTAG = OFF |
| A7 JTAG          | RECOVERY_RTS | Pull-Down | Pull-down resistor is on module. A7 JTAG = OFF |

We managed to boot the board in the recovery mode by connecting DEBUG_RTS to 3.3v,
but experimenting with DEBUG_TXD, IO1_TXD, and RECOVERY_RTS didn't produce any
visible effects, which is how we started looking at the pins on the chip itself.

It could be that to enable JTAG, you need to [pull all these three up].  Or maybe
it won't work at all.

There is another [datasheet with schematics] where these pins are mentioned
(search for "Strapping").

## Hardware Attacks

While talking about the hardware, it's worth mentioning that there are few
attacks that can be tried here, such as voltage and clock glitching (to alter
instructions such as comparisons before signature checking) as well as [chip
decapping] (to read out the masked ROM and perform optical fault injection).

Again, due to time constraints, we only tried a naive voltage glitching attack.
Specifically, we connected an FPGA to a MOSFET circuit and a step up converter.
The converter is necessary because the FPGA board can only supply 3.3v while
the dev board uses 5v when powered externally.  This allowed us to cut the
power to the board for a few nanoseconds (based on the FPGA clock cycles).

We connected to the debug UART to monitor the system for any interesting
messages since we didn't have a better way to get output from the device.
On the device itself, we just tried to supply the capabilities file with all
debugging features enabled.  This is not allowed and we didn't have the right
signature, hence the need for glitching.

Here's some interim version of our glitcher written for [Arty A7-35T]:

```verilog
module glitcher(
    input  i_clk,         // e3: 100 MHz crystal oscillator
    input  i_clk_reset,   // c2: clock reset button

    input  i_glitch,      // sw0 (a8): glitch vcc input

    input i_pulse,        // btn0 (d9): drop voltage (glitch)
    input i_pulse_reset,  // btn1 (c9): press the reset button (glitch)

    output o_clk,         // pmod ja, pin2 (b11): 200 MHz clock
    output o_clk_locked,  // pmod ja, pin3 (a11): clock ready
    output o_clk_led,     // ld5 (j5): clock status led

    output reg o_glitch,  // pmod ja, pin 1 (g13): glitch output
    output reg o_glitch_reset,  // pmod jd, pin 1 (d4): reset button output

    output o_glitch_led   // ld4 (h5): glitch status led

    // output reg [15:0] o_counter  // glitch counter (for testing)
);

reg [15:0] o_counter;

// 100 to 200 MHz clock.
clk clk0(
    .reset(!i_clk_reset),  // high at rest; low when pressed
    .i_clk(i_clk),
    .o_clk(o_clk),
    .o_locked(o_clk_locked)
);

assign o_clk_led = o_clk_locked;

assign o_glitch_led = i_glitch;

// Power line (5V) glitching dependent on the clock.
always @(posedge o_clk or negedge i_clk_reset)
    if (!i_clk_reset)
        o_counter <= 0;
    else
        o_counter <= o_counter + 1;

always @(*)
begin
    if (i_pulse && o_counter <= 1000)
    // if (i_pulse && (o_counter % 4) == 0)
        o_glitch = 0;
    else
        o_glitch = i_glitch;
end

// Reset line glitching.
always @(*)
begin
    if (i_pulse_reset && o_counter <= 800)
    // if (i_pulse_reset && (o_counter % 800) == 0)
        o_glitch_reset = i_glitch;
    else
        o_glitch_reset = 0;
end

endmodule
```

(We also soldered wires to the reset button and connected to it via another
MOSFET circuit.)

The `clk` module is provided by the Xilinx IP library and was configured using
Clocking Wizard to boost up the FPGA clock to 200 MHz, which is the maximum
frequency of the M4 core.

There are a lot of problems with this approach.  First, the board has brown out
detection, so it just resets when a voltage drop is detected (there's some
threshold, but we don't know whether our glitches had any effect at all).
There are several tiny capacitors on the board, which smooth out voltage drops,
which we didn't try removing because it required more work.  Second, we didn't
have access to proper equipment such as [ChipWhisperer] to perform
measurements and specify advanced triggers.  Third, the test program we came up
with was too long, it would have been better to glitch in a tight loop, but we
couldn't think of anything else.  Fourth, the clock speed of the device might
be too high (limiting the glitch window even further).  We didn't try
desoldering the clocks on the dev board and supplying our own from the FPGA
(this was way before we tried to desolder the main chip).

The reason we tried voltage glitching in the first place is because it was
successfully used in the past by multiple parties:

- [PS3]
- [Xbox 360]
- [Microchip SAM L11]
- [Nintendo Switch].

It worked for PS3 with a manual trigger because the test itself was better.
For the 360, there was a mechanism to slow down the device clock.  In the other
cases, proper equipment was used to perform power analysis and to trigger
automatically.  The Switch talk explains on the physical component level why
you need to be very precise.

The reason we even started playing with voltage glitching is because the system
sometimes printed interesting messages when you pressed the reset button
repeatedly very fast:

```
5b 31 42 4c 5d 20 42 4f 4f 54 3a 20 34 30 35 30  [1BL] BOOT: 4050
30 30 30 30 2f 30 30 30 30 30 30 30 30 2f 30 34  0000/00000000/04
30 32 30 30 30 30 0d 0a 47 3d 61 64 37 65 30 36  020000..G=ad7e06
62 33 64 61 65 30 36 34 35 66 37 33 64 65 38 65  b3dae0645f73de8e
38 30 32 37 62 32 31 61 32 66 31 62 61 62 61 32  8027b21a2f1baba2
61 31 36 39 37 38 37 61 66 31 36 34 37 64 32 61  a169787af1647d2a
31 66 38 37 64 39 65 33 65 66 38 35 34 32 62 33  1f87d9e3ef8542b3
34 65 66 38 30 65 61 66 65 61 36 35 62 31 34 35  4ef80eafea65b145
36 64 64 30 36 38 34 32 36 36 62 62 36 30 63 38  6dd0684266bb60c8
37 39 65 31 63 34 64 34 34 39 37 36 35 37 39 37  79e1c4d449765797
31 62 32 34 64 37 61 31 35 32 0d 0a 5b 31 42 4c  1b24d7a152..[1BL
5d 20 42 41 43 4b 55 50 20 50 4c 55 54 4f 4e 2d  ] BACKUP PLUTON-
52 54 0d 0a 44 3d 30 30 36 66 65 36 32 39 62 65  RT..D=006fe629be
62 36 39 66 63 33 62 62 30 36 63 66 38 34 39 34  b69fc3bb06cf8494
63 63 63 32 35 34 36 31 66 35 39 37 61 61 65 30  ccc25461f597aae0
37 36 61 61 30 64 31 66 39 62 34 39 36 35 36 64  76aa0d1f9b49656d
36 30 62 36 33 35 35 37 62 65 63 61 64 36 35 62  60b63557becad65b
33 33 38 61 31 61 35 62 34 31 30 34 66 37 36 39  338a1a5b4104f769
36 34 39 61 61 61 33 35 33 34 30 65 63 61 31 66  649aaa35340eca1f
31 38 39 39 64 66 36 31 30 33 30 35 35 30 36 63  1899df610305506c
64 37 62 65 65 38 2c 4e 3d 64 32 34 63 65 38 35  d7bee8,N=d24ce85
34 62 62 37 65 62 33 61 62 61 30 36 63 30 66 30  4bb7eb3aba06c0f0
35 64 61 65 31 37 64 32 61 63 65 65 66 37 34 62  5dae17d2aceef74b
30 66 62 61 63 33 61 34 61 30 38 37 65 63 32 30  0fbac3a4a087ec20
61 38 65 62 32 63 30 39 30 0d 0a 5b 50 4c 55 54  a8eb2c090..[PLUT
4f 4e 5d 20 4c 6f 67 67 69 6e 67 20 69 6e 69 74  ON] Logging init
69 61 6c 69 7a 65 64 0d 0a 5b 50 4c 55 54 4f 4e  ialized..[PLUTON
5d 20 42 6f 6f 74 69 6e 67 20 48 4c 4f 53 20 63  ] Booting HLOS c
6f 72 65 0d 0a 5b 50 4c 55 54 4f 4e 5d 20 42 4f  ore..[PLUTON] BO
4f 54 49 4e 47 20 42 41 43 4b 55 50 20 73 65 63  OTING BACKUP sec
75 72 69 74 79 20 6d 6f 6e 69 74 6f 72 0d 0a     urity monitor.. 
5b 31 42 4c 5d 20 42 4f 4f 54 3a 20 34 30 36 31  [1BL] BOOT: 4061
30 30 30 30 2f 30 30 30 30 31 31 63 30 2f 30 35  0000/000011c0/05
30 32 30 30 30 30 0d 0a 47 3d 61 64 37 65 30 36  020000..G=ad7e06
62 33 64 61 65 30 36 34 35 66 37 33 64 65 38 65  b3dae0645f73de8e
38 30 32 37 62 32 31 61 32 66 31 62 61 62 61 32  8027b21a2f1baba2
61 31 36 39 37 38 37 61 66 31 36 34 37 64 32 61  a169787af1647d2a
31 66 38 37 64 39 65 33 65 66 38 35 34 32 62 33  1f87d9e3ef8542b3
34 65 66 38 30 65 61 66 65 61 36 35 62 31 34 35  4ef80eafea65b145
36 64 64 30 36 38 34 32 36 36 62 62 36 30 63 38  6dd0684266bb60c8
37 39 65 31 63 34 64 34 34 39 37 36 35 37 39 37  79e1c4d449765797
31 62 32 34 64 37 61 31 35 32 0d 0a 44 3d 30 30  1b24d7a152..D=00
36 66 65 36 32 39 62 65 62 36 39 66 63 33 62 62  6fe629beb69fc3bb
30 36 63 66 38 34 39 34 63 63 63 32 35 34 36 31  06cf8494ccc25461
66 35 39 37 61 61 65 30 37 36 61 61 30 64 31 66  f597aae076aa0d1f
39 62 34 39 36 35 36 64 36 30 62 36 33 35 35 37  9b49656d60b63557
62 65 63 61 64 36 35 62 33 33 38 61 31 61 35 62  becad65b338a1a5b
34 31 30 34 66 37 36 39 36 34 39 61 61 61 33 35  4104f769649aaa35
33 34 30 65 63 61 31 66 31 38 39 39 64 66 36 31  340eca1f1899df61
30 33 30 35 35 30 36 63 64 37 62 65 65 38 2c 4e  0305506cd7bee8,N
3d 64 30 62 32 63 35 39 39 65 37 35 65 33 34 37  =d0b2c599e75e347
62 34 34 34 64 30 64 61 63 31 33 66 36 62 65 61  b444d0dac13f6bea
34 39 65 64 62 61 36 31 33 38 37 31 33 65 31 39  49edba6138713e19
65 31 64 34 34 35 33 65 37 33 66 66 32 39 64 36  e1d4453e73ff29d6
34 0d 0a 5b 50 4c 55 54 4f 4e 5d 20 4c 6f 67 67  4..[PLUTON] Logg
69 6e 67 20 69 6e 69 74 69 61 6c 69 7a 65 64 0d  ing initialized.
0a 5b 50 4c 55 54 4f 4e 5d 20 42 6f 6f 74 69 6e  .[PLUTON] Bootin
67 20 48 4c 4f 53 20 63 6f 72 65 0d 0a           g HLOS core..
```

Note that in the context of the bounty, this was just a waste of time because
physical attacks are out of scope and hardware debugging was just a nice to
have in order to understand the system better.

## SDK

To communicate with and program the device, you need to install the [SDK].
This helped with reverse engineering quite a bit because the DLLs that come
with it are written in C#.  And after decompiling them, it's almost as good as
having source code. [dnSpy] and [dotPeek] are the tools you might want to use
for this.

On Windows, the DLLs are stored in these directories:

```
C:\Program Files (x86)\Azure Sphere Device Communication Service
C:\Program Files (x86)\Microsoft Azure Sphere SDK\Tools
```

And the logs here:

```
C:\Users\<USER>\AppData\Local\Azure Sphere Tools\Logs
```

The logs may contain more information than the verbose mode of the `azsphere`
tool.  For instance, we used them to read hex bytes of messages sent during
recovery.

## Recovery

Speaking of recovery, the device can be recovered (reflashed) with a set of signed
images.  It's also possible to pass the device capability file and the recovery
directory as parameters:

```
azsphere device recover -c appdevelopment.cfg -i extracted_20_05 -v
```

Without these, the recovery files will be downloaded from:

```
https://prod.releases.sphere.azure.net/recovery/mt3620an.zip
```

There's also a different URL, which is likely used for beta releases since
the new images appear there sooner:

```
https://int.releases.sphere.azure.net/recovery/mt3620an.zip
```

The new images are released every month.

## Capabilities

The device capability file is downloaded from a URL like this by making a POST
request:

```
POST https://prod.core.sphere.azure.net/v2/tenants/ae5e6fa5-cfab-4b68-bb68-8abe9bf5677d/deviceCapabilityImage/
```

A tool like [Fiddler] can be used to MITM this connection, but the server
doesn't allow us requesting any interesting capabilities.  It seems there's
just a loop which allows setting capabilities 11 and 13.  The best we could do
here is to request a capability file with many of these repeated, but it didn't
produce any interesting results on the device.  We couldn't trick the server
into producing a corrupted and signed capability file either.

Here's the capabilities decompiled from the SDK:

```c#
dictionary.Add((DeviceCapabilityType) 1, "Allow test key signed software");
dictionary.Add((DeviceCapabilityType) 2, "Enable Pluton debugging");
dictionary.Add((DeviceCapabilityType) 3, "Enable A7 debugging");
dictionary.Add((DeviceCapabilityType) 4, "Enable N9 debugging");
dictionary.Add((DeviceCapabilityType) 5, "Enable A7 GDB debugging");
dictionary.Add((DeviceCapabilityType) 6, "Enable IO M4 1 debugging");
dictionary.Add((DeviceCapabilityType) 7, "Enable IO M4 2 debugging");
dictionary.Add((DeviceCapabilityType) 8, "Enable A7 Console");
dictionary.Add((DeviceCapabilityType) 9, "Enable SLT Loader");
dictionary.Add((DeviceCapabilityType) 10, "Enable System Software development");
dictionary.Add((DeviceCapabilityType) 11, "Enable App development");
dictionary.Add((DeviceCapabilityType) 12, "Enable RF test mode");
dictionary.Add((DeviceCapabilityType) 13, "Enable field servicing");
```

There are a few interesting ones here, but these can't be enabled at will
because the file itself is signed and its signature is checked
when it's loaded by the device.

## Recovery Process

Here's an example recovery output:

```
Azure Sphere Utility version 20.4.7.42974
Copyright (C) Microsoft Corporation. All rights reserved.
Start time (UTC): Monday, 29 June 2020 14:36:34
Starting device recovery. Please note that this may take up to 10 minutes.
verbose: Looking for device locators in assembly C:\Program Files (x86)\Microsoft Azure Sphere SDK\Tools\DeviceControl.Common.dll:
verbose: Looking for device locators in assembly C:\Program Files (x86)\Microsoft Azure Sphere SDK\Tools\DeviceControl.Ftdi.dll:
verbose: Looking for device locators in assembly C:\Program Files (x86)\Microsoft Azure Sphere SDK\Tools\DeviceControl.MsftDevBoards.dll:
verbose: - Found MT3620 device
verbose: Found recovery images for the v2 recovery protocol.
verbose: Adding image package for recovery.imagemanifest
verbose: Adding image package for e5a6b6eed0ef432ba24c9e07f4198d30.bin
verbose: Adding image package for 31847582fa2f4581b5b18d339e6a4873.bin
verbose: Adding image package for b40ace52f2de46728da066f5165be8b6.bin
verbose: Adding image package for 92854503e1a4425ab9a81f990b6f03bc.bin
verbose: Adding image package for 80490e15d7194692be598a61585b2ec6.bin
verbose: Adding image package for 6471c5a8d6f84a9995442d7ed2113092.bin
verbose: Adding image package for e1a9cb58c77b44e8b67b9bc2aece076b.bin
verbose: Adding image package for 2b9b33b4d6a040f09cc675a3003979be.bin
verbose: Adding image package for recovery-runtime.bin
verbose: Adding image package for e6159560434f47e89376b67d030628f8.bin
verbose: Adding image package for 9db8ef72fb814f72a4624b274b1caf22.bin
verbose: Adding image package for 0a9e76d0cee44716a5498dc72db215e0.bin
verbose: Adding image package for e783ef2f538441d99b8edf9a3d88dec2.bin
verbose: Adding image package for 600bca2d11e24df2a4ef766619614d02.bin
verbose: Adding image package for 7cb47d0f000341a4878f65c4b998ce03.bin
verbose: Adding image package for 15f454190ad54d7da411ee70798f82b4.bin
verbose: Adding image package for 3bceac8b52b247d3a2bb79414b5160fd.bin
verbose: No SerialSlipToTunService port is set in the registry; defaulting to 48938.
verbose: Looking for board using device locator 'MT3620 device'
verbose: Taken device enumeration lock.
verbose: Released file mutex.
verbose: Located board(s) using device locator 'MT3620 device'
verbose: Taken device enumeration lock.
verbose: Released file mutex.
Board found. Sending recovery bootloader.
verbose: Unexpected data while waiting for recovery mode:  (0 bytes) - will wait for XMODEM
verbose: Sending 16384 bytes by XMODEM...
verbose: 16384 bytes sent.
verbose: XMODEM sent 16384 bytes (of 16384 total)
verbose: Recovery 1BL booted: POST code 380a0500/00000001/02000000
verbose: Recovery boot successful
verbose: Received Initialize
verbose: Version 1
verbose: Device ID:
006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8
verbose: Received RecoveryEvent: BLInitializationComplete
verbose: Received LogConfigQuery - logging disabled
verbose: Received ImageRequestCapability: Capability available.
verbose: File transfer request: Sending 392 bytes (of 392 total), starting at 0.
verbose: Sending 392 bytes by XMODEM...
verbose: 392 bytes sent.
verbose: Received RecoveryEvent: BLCapabilityImageReceived
verbose: Received RecoveryEvent: BLCapabilityImageLoaded
verbose: Received ImageRequestByFilename: recovery-runtime.bin
verbose: File 'recovery-runtime.bin' available.
verbose: File transfer request: Sending 60836 bytes (of 60836 total), starting at 0.
verbose: Sending 60836 bytes by XMODEM...
verbose: 60836 bytes sent.
verbose: Received LogConfigQuery - logging disabled
verbose: Received RecoveryEvent: RABootComplete
verbose: Received BaudrateSwitchQuery: Switching to higher baud rate
verbose: Received StatusRequest: returning ServerReady
verbose: Received RecoveryEvent: RAEraseFlashStarted
Erasing flash.
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Received RecoveryEvent: RAEraseFlashComplete
verbose: Received ImageRequestByFilename: recovery.imagemanifest
verbose: File 'recovery.imagemanifest' available.
verbose: File transfer request: Sending 1496 bytes (of 1496 total), starting at 0.
verbose: Sending 1496 bytes by XMODEM...
verbose: 1496 bytes sent.
verbose: Received RecoveryEvent: RAManifestReceived
verbose: Received RecoveryEvent: RAManifestProcessed
verbose: ProgressUpdate received: 17 images remaining of 17 (5390752 bytes of 5390752
Sending 17 images. (5390752 bytes to send)
verbose: Received ImageRequestByFilename: 92854503e1a4425ab9a81f990b6f03bc.bin
verbose: File '92854503e1a4425ab9a81f990b6f03bc.bin' available.
verbose: File transfer request: Sending 2376 bytes (of 2376 total), starting at 0.
verbose: Sending 2376 bytes by XMODEM...
verbose: 2376 bytes sent.
verbose: ProgressUpdate received: 16 images remaining of 17 (5388376 bytes of 5390752
Sent 1 of 17 images. (5388376 of 5390752 bytes remaining)
verbose: Received ImageRequestByFilename: 2b9b33b4d6a040f09cc675a3003979be.bin
verbose: File '2b9b33b4d6a040f09cc675a3003979be.bin' available.
verbose: File transfer request: Sending 20480 bytes (of 26860 total), starting at 0.
verbose: Sending 20480 bytes by XMODEM...
verbose: 20480 bytes sent.
verbose: Received ImageRequestByFilename: 2b9b33b4d6a040f09cc675a3003979be.bin
verbose: File '2b9b33b4d6a040f09cc675a3003979be.bin' available.
verbose: File transfer request: Sending 6380 bytes (of 26860 total), starting at 20480.
verbose: Sending 6380 bytes by XMODEM...
verbose: 6380 bytes sent.
verbose: ProgressUpdate received: 15 images remaining of 17 (5361516 bytes of 5390752
Sent 2 of 17 images. (5361516 of 5390752 bytes remaining)
...
Sent 17 of 17 images. (0 of 5390752 bytes remaining)
verbose: Timed out reading frame (read 0 bytes before timeout)
verbose: Received RecoveryEvent: RARecoveryComplete
verbose: Received RecoveryComplete
Finished writing images; rebooting board.
Device ID: 006FE629BEB69FC3BB06CF8494CCC25461F597AAE076AA0D1F9B49656D60B63557BECAD65B338A1A5B4104F769649AAA35340ECA1F1899DF610305506CD7BEE8
Device recovered successfully.
Command completed in 00:03:59.1014696.
```

This mode can be either enabled by the SDK or by connecting DEBUG_RTS to 3.3v
before booting the device.

The [XMODEM] protocol is used to transfer files to the device.  We think that
the first file is requested by the boot ROM because we couldn't find any of the
printed messages in the recovery files.  Each file is signed and its signature
is validated.  You can trick the recovery into accepting a different signed
bootloader (the file type is checked as well), but this doesn't produce any
interesting effects.  Or you can terminate the connection in the middle of the
recovery process, but the most privileged components are loaded first, so you
can't just get a semi-working system without a security subsystem present on
the device.

There's also a binary protocol that's used to request files, but it's mostly
device-controlled.  The client can only respond to certain messages.  The best
you can do here is to pass invalid file sizes, but that didn't produce any
interesting results.

You can get the full picture by decompiling the SDK, but here are just some
protocol types:

```c#
namespace RecoveryLibrary.ProtocolV2.ControlProtocol
{
  public enum ClientMessageType : ushort
  {
    RequestUnknown,          // 0
    Initialization,          // 1
    StatusRequest,           // 2
    BaudrateSwitchQuery,     // 3
    ImageRequestCapability,  // 4
    ImageRequestManifest,    // 5
    ImageRequestRecoveryApp, // 6
    ImageRequestByFilename,  // 7
    ProgressUpdate,          // 8
    LogConfigQuery,          // 9
    LogEntry,                // 0xa
    RecoveryEvent,           // 0xb
    RecoveryError,           // 0xc
    RecoveryComplete,        // 0xd
  }
}

namespace RecoveryLibrary.ProtocolV2.ControlProtocol
{
  public enum ServerMessageType : ushort
  {
    InitializationAck = 160, // 0x00A0
    ServerReady = 161, // 0x00A1
    StatusBusy = 162, // 0x00A2
    SimpleQueryAck = 163, // 0x00A3
    ImageRequestAck = 164, // 0x00A4
    ImageRequestError = 165, // 0x00A5
    AbortRecovery = 166, // 0x00A6
  }
}

namespace RecoveryLibrary.ProtocolV2.ControlProtocol
{
  public enum ResponseType
  {
    None,
    SendResponseMessage,
    SendResponseMessageAndAbort,
    SendResponseMessageAndTransferContent,
    SendResponseMessageAndSwitchBaudRate,
    RecoveryError,
    RecoveryComplete,
  }
}
```

Here's the log from the tool we wrote showing the start of the recovery
process:

```
[>] Output: b'CCCCCCC'
[<] Sending recovery 1BL
[>] Output: b'+GOOD\r\n'
[>] Output: b'[1BL] BOOT: 380a0300/00000001/02000000\r\n'
[>] Output: b'\x02\x89\x02\x01\x02\x85\x02\x01\x01\x01\x81006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x03\xbe\x03\x00'
[>] Decoded COBS: b'\x89\x00\x01\x00\x85\x00\x01\x00\x00\x00006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x00\xbe\x03'
[>] Decoded UART: b'\x01\x00\x85\x00\x01\x00\x00\x00006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x00'
[>] Leftovers: b''
[<] Payload: b'\xa0\x00\x00\x00'
[<] Encoded UART: b'\x04\x00\xa0\x00\x00\x00\xd7\xec'
[<] Encoded COBS: b'\x02\x04\x02\xa0\x01\x01\x03\xd7\xec\x00'
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x01I\xb2\x00\x02\x04\x02\t\x01\x01\x03\xd6\xf5\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x01I\xb2'
[>] Decoded UART: b'\x0b\x00\x01\x00\x01'
[>] Leftovers: b'\x02\x04\x02\t\x01\x01\x03\xd6\xf5\x00'
[>] Decoded COBS: b'\x04\x00\t\x00\x00\x00\xd6\xf5'
[>] Decoded UART: b'\t\x00\x00\x00'
[>] Leftovers: b''
[<] Payload: b'\xa3\x00\x01\x00\x00'
[<] Encoded UART: b'\x05\x00\xa3\x00\x01\x00\x00!\x8a'
[<] Encoded COBS: b'\x02\x05\x02\xa3\x02\x01\x01\x03!\x8a\x00'
[>] Output: b'\x02\x0c\x02\x04\x02\x08\x01\x01\x01\x01\x07\xff\xff\xff\xff\x9e\xc8\x00'
[>] Decoded COBS: b'\x0c\x00\x04\x00\x08\x00\x00\x00\x00\x00\xff\xff\xff\xff\x9e\xc8'
[>] Decoded UART: b'\x04\x00\x08\x00\x00\x00\x00\x00\xff\xff\xff\xff'
[>] Leftovers: b''
[<] Payload: b'\xa4\x00\x0c\x00\x00\x00\x00\x00\x88\x01\x00\x00\x88\x01\x00\x00'
[<] Encoded UART: b'\x10\x00\xa4\x00\x0c\x00\x00\x00\x00\x00\x88\x01\x00\x00\x88\x01\x00\x00w\x1e'
[<] Encoded COBS: b'\x02\x10\x02\xa4\x02\x0c\x01\x01\x01\x01\x03\x88\x01\x01\x03\x88\x01\x01\x03w\x1e\x00'
[<] Sending device capabilities
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x02*\x82\x00\x02\x05\x02\x0b\x02\x01\x04\x03\x0b\x92\x00\x02!\x02\x07\x02\x1d\x01\x01\x01\x01\x19\xff\xff\xff\xffrecovery-runtime.bin\x03A\xf0\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x02*\x82'
[>] Decoded UART: b'\x0b\x00\x01\x00\x02'
[>] Leftovers: b'\x02\x05\x02\x0b\x02\x01\x04\x03\x0b\x92\x00\x02!\x02\x07\x02\x1d\x01\x01\x01\x01\x19\xff\xff\xff\xffrecovery-runtime.bin\x03A\xf0\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x03\x0b\x92'
[>] Decoded UART: b'\x0b\x00\x01\x00\x03'
[>] Leftovers: b'\x02!\x02\x07\x02\x1d\x01\x01\x01\x01\x19\xff\xff\xff\xffrecovery-runtime.bin\x03A\xf0\x00'
[>] Decoded COBS: b'!\x00\x07\x00\x1d\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery-runtime.bin\x00A\xf0'
[>] Decoded UART: b'\x07\x00\x1d\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery-runtime.bin\x00'
[>] Leftovers: b''
[<] Payload: b'\xa4\x00\x0c\x00\x00\x00\x00\x00\xa4\xed\x00\x00\xa4\xed\x00\x00'
[<] Encoded UART: b'\x10\x00\xa4\x00\x0c\x00\x00\x00\x00\x00\xa4\xed\x00\x00\xa4\xed\x00\x00\x0c\x93'
[<] Encoded COBS: b'\x02\x10\x02\xa4\x02\x0c\x01\x01\x01\x01\x03\xa4\xed\x01\x03\xa4\xed\x01\x03\x0c\x93\x00'
[<] Sending recovery runtime
[>] Output: b'\x02\x04\x02\t\x01\x01\x03\xd6\xf5\x00'
[>] Decoded COBS: b'\x04\x00\t\x00\x00\x00\xd6\xf5'
[>] Decoded UART: b'\t\x00\x00\x00'
[>] Leftovers: b''
[<] Payload: b'\xa3\x00\x01\x00\x00'
[<] Encoded UART: b'\x05\x00\xa3\x00\x01\x00\x00!\x8a'
[<] Encoded COBS: b'\x02\x05\x02\xa3\x02\x01\x01\x03!\x8a\x00'
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x06\xae\xc2\x00\x02\x04\x02\x03\x01\x01\x03}\x9d\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x06\xae\xc2'
[>] Decoded UART: b'\x0b\x00\x01\x00\x06'
[>] Leftovers: b'\x02\x04\x02\x03\x01\x01\x03}\x9d\x00'
[>] Decoded COBS: b'\x04\x00\x03\x00\x00\x00}\x9d'
[>] Decoded UART: b'\x03\x00\x00\x00'
[>] Leftovers: b''
[<] Payload: b'\xa3\x00\x01\x00\x00'
[<] Encoded UART: b'\x05\x00\xa3\x00\x01\x00\x00!\x8a'
[<] Encoded COBS: b'\x02\x05\x02\xa3\x02\x01\x01\x03!\x8a\x00'
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x07\x8f\xd2\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x07\x8f\xd2'
[>] Decoded UART: b'\x0b\x00\x01\x00\x07'
[>] Leftovers: b''
[i] Waiting for flash erase to complete
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x08`#\x00\x02#\x02\x07\x02\x1f\x01\x01\x01\x01\x1b\xff\xff\xff\xffrecovery.imagemanifest\x03\xa4\x10\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x08`#'
[>] Decoded UART: b'\x0b\x00\x01\x00\x08'
[>] Leftovers: b'\x02#\x02\x07\x02\x1f\x01\x01\x01\x01\x1b\xff\xff\xff\xffrecovery.imagemanifest\x03\xa4\x10\x00'
[>] Decoded COBS: b'#\x00\x07\x00\x1f\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery.imagemanifest\x00\xa4\x10'
[>] Decoded UART: b'\x07\x00\x1f\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery.imagemanifest\x00'
[>] Leftovers: b''
...
```

In the C# code, you might want to look at these symbols:

```c#
EncapsulatePayload
ExtractPayload
CalculateCrc
WaitForRecoveryBoot, VerifyBootMessage, DeviceResponses
ServerMessageType, ControlProtocol
BuildResponse, SimpleAckResponse
RequestFileBase
```

When the board is in the recovery mode, you should see this:

```
RECOVERY
0000362000008A01020A00008FC8C833
CCC
```

`C`s mean that this is XMODEM with CRC-16 and the receiver is ready to
receive data.

Note that [COBS] is used for encoding protocol messages.  Also, the board
requests to switch to a higher baud rate during the recovery process.

```c#
Baudrate settings:
{
  PortMode.Bootloader,
  new SerialPortConfiguration()
  {
    BaudRate = 115200,
    Parity = Parity.None,
    DataBits = 8,
    StopBits = StopBits.One,
    Handshake = Handshake.None
  }
},
{
  PortMode.ImagingMt3620,
  new SerialPortConfiguration()
  {
    BaudRate = 3000000,
    Parity = Parity.None,
    DataBits = 8,
    StopBits = StopBits.One,
    Handshake = Handshake.RequestToSend
  }
},
{
  PortMode.ImagingMt3620LowSpeed,
  new SerialPortConfiguration()
  {
    BaudRate = 115200,
    Parity = Parity.None,
    DataBits = 8,
    StopBits = StopBits.One,
    Handshake = Handshake.RequestToSend
  }
}
```

Some example messages:

```python
# Format:
# \x07\x00 -- ClientMessageType.ImageRequestByFilename
# \x1d\x00 -- size (29, little-endian)
# \x00\x00\x00\x00 -- index?
# \xff\xff\xff\xff -- file size?
# recovery-runtime.bin -- filename
# \x00 -- terminator
output, leftovers = smart_decode(serial, leftovers)
assert output == b"\x07\x00\x1d\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery-runtime.bin\x00"

# Format:
# \xa4\x00 -- ServerMessageType.ImageRequestAck (0x00a4)
# \x0c\x00 -- payload size (12, little-endian)
# \x00\x00\x00\x00 -- start index?
# \xa4\xed\x00\x00 -- send size?
# \xa4\xed\x00\x00 -- total size?
write_encode(
    serial,
    (b"\xa4\x00"
     b"\x0c\x00"
     b"\x00\x00\x00\x00"
     b"\xa4\xed\x00\x00"
     b"\xa4\xed\x00\x00"))
```

The XMODEM protocol is pretty simple and the client has limited control over
supplied data, which significantly decreases the likelihood of finding bugs
here.  After messing with the message sizes and signatures for a bit, we moved
on to other things.  There might be issues, but we just didn't have the time to
reverse the firmware in depth.  And doing so with static analysis only is
rather difficult.

Each file in the recovery has metadata and is signed with ECDSA.

## 010 Templates

Here are the templates for 010 Editor.

image_manifest.bt:
```c
// Azure Sphere Image Manifest format.
// '$SDK_ROOT/Tools/image_manifest.dll' contains the format parsing code.
// Used in recovery image files, see 'azsphere device recover --help'.

#include "common.bt"

struct ManifestHeader  // V3
{
    UINT16 Version <format=hex>;
    UINT16 ImageCount;
    UINT16 ManifestHeaderSize <format=hex>;
    UINT16 ManifestEntrySize <format=hex>;
    UINT64 BuildDate <format=hex>;  // note this is serialized as U8
};

struct ManifestIdentity  // V3
{
    UINT32 Version <format=hex>;
    IdentityType Type;
};

typedef struct {
    UINT32 Data1 <format=hex>;
    UINT16 Data2 <format=hex>;
    UINT16 Data3 <format=hex>;
    UBYTE Data4[8] <format=hex>;
} Guid <read=ReadGuid>;

string ReadGuid(Guid &guid)
{
    local string s;

    SPrintf(s,
        "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]);

    return s;
}

typedef enum <UINT16>
{
    Invalid = 0,
    Firmware = 1,
    Backups = 2,
    Applications_ = 4,
    LogStorage = 5,
    NwConfig = 6,
    BootloaderOne = 7,
    BootloaderOneBackup = 8,
    LocatorTable = 9,
    LocatorTableBackup = 10, // 0x000A
    BlockHashes = 11, // 0x000B
    BlockHashesBackup = 12, // 0x000C
    BootManifest_ = 13, // 0x000D
    BootManifestBackup = 14, // 0x000E
    // LastValidPhysicalPartition = 15, // 0x000F
    TelemetryStorage = 15, // 0x000F
    MaxPhysicalLayout = 16383, // 0x3FFF
    EcRuntimeProtectedRange = 16384, // 0x4000
    MaxVirtualLayout = 65535, // 0xFFFF
} PartitionType <read=ReadPartitionType>;

string ReadPartitionType(PartitionType part_type)
{
    local string s;

    switch (part_type) {
        case 0:     s = "invalid"; break;
        case 1:     s = "firmware"; break;
        case 2:     s = "backups"; break;
        case 4:     s = "applications"; break;
        case 5:     s = "log storage"; break;
        case 6:     s = "nw config"; break;
        case 7:     s = "bootloader one"; break;
        case 8:     s = "bootloader one backup"; break;
        case 9:     s = "locator table"; break;
        case 10:    s = "locator table backup"; break;
        case 11:    s = "block hashes"; break;
        case 12:    s = "block hashes backup"; break;
        case 13:    s = "boot manifest"; break;
        case 14:    s = "boot manifest backup"; break;
        // case 15:    s = "last valid physical partition"; break;
        case 15:    s = "telemetry storage"; break;
        case 16383: s = "max physical layout"; break;
        case 16384: s = "ec runtime protected range"; break;
        case 65535: s = "max virtual layout"; break;
    }

    return s;
}

struct ManifestEntry  // V3
{
    Guid ImageUid;
    Guid ComponentUid;
    ImageType Type <format=hex>;
    PartitionType PartType <format=hex>;
    UINT32 ImageFileSize <format=hex>;
    UINT32 UncompressedImageSize <format=hex>;
    ManifestIdentity Provides[2];
    ManifestIdentity DependsOn[2];
};


// Tip: compare 'ManifestHeader.BuildDate' (Unix time) against the 'Linux
// version' string in one of the binaries, which includes the build date.
ManifestHeader hdr;

local int image_index;
local int id_index;
local int provides_size;
local int depends_size;
for (image_index = 0; image_index < hdr.ImageCount; ++image_index) {
    ManifestEntry entry;

    if (image_index != 0) {
        Printf("\n");
    }

    Printf("index: %d\n", image_index);
    Printf("image uid:               %s\n", ReadGuid(entry.ImageUid));
    Printf("component uid:           %s\n", ReadGuid(entry.ComponentUid));
    Printf("type:                    %s\n", ReadImageType(entry.Type));
    Printf("partition type:          %s\n", ReadPartitionType(entry.PartType));
    Printf("image file size:         0x%08x\n", entry.ImageFileSize);
    Printf("uncompressed image size: 0x%08x\n", entry.UncompressedImageSize);

    provides_size = sizeof(entry.Provides)  / sizeof(entry.Provides[0]);
    depends_size  = sizeof(entry.DependsOn) / sizeof(entry.DependsOn[0]);

    for (id_index = 0; id_index < provides_size; ++id_index) {
        Printf("provides[%d].version:     0x%08x\n",
            id_index,
            entry.Provides[id_index].Version);

        Printf("provides[%d].type:        %s\n",
             id_index,
             ReadIdentityType(entry.Provides[id_index].Type));
    }

    for (id_index = 0; id_index < depends_size; ++id_index) {
        Printf("depends[%d].version:      0x%08x\n",
            id_index,
            entry.DependsOn[id_index].Version);

        Printf("depends[%d].type:         %s\n",
            id_index,
            ReadIdentityType(entry.DependsOn[id_index].Type));
    }
}

#include "image_metadata.bt"
```

image_metadata.bt:
```c
// Azure Sphere Extensible Metadata format.
// '$SDK_ROOT/Tools/image_metadata.dll' contains the format parsing code.
// Used in recovery image files, see 'azsphere device recover --help'.

#include "common.bt"

LittleEndian();

// Types.

struct ImageMetadataHeader
{
    UINT32 MagicValue <format=hex>;
    UINT32 SectionCount <format=hex>;
};

local UINT32 expected_magic = 0x4d345834;  // 4X4M

enum <USHORT> MetadataSectionId
{
    None = 0,
    Debug = 16964, // 0x4244
    LegacyABIDepends = 17473, // 0x4441
    Identity = 17481, // 0x4449
    ABIDepends = 17486, // 0x444E
    Legacy = 18252, // 0x474C
    Signature = 18259, // 0x4753
    Compression = 19779, // 0x4D43
    RequiredFlashOffset = 20306, // 0x4F52
    LegacyABIProvides = 20545, // 0x5041
    ABIProvides = 20558, // 0x504E
    TemporaryImage = 20564, // 0x5054
    Revocation = 22098, // 0x5652
};

struct ImageMetadataSectionHeader
{
    MetadataSectionId SectionId;
    ushort DataLength <format=hex>;
};

struct IdentityMetadataSection
{
    ImageType Type;
    USHORT reserved <format=hex>;
    UBYTE ComponentUid[16] <format=hex>;
    UBYTE ImageUid[16] <format=hex>;
    // Methods omitted.
};

enum <UINT32> SigningType
{
    InvalidSigningType,
    ECDsa256,
};

struct SignatureMetadataSection  // subclass of ImageMetadataSection
{
    UBYTE SigningCertThumbprint[20] <format=hex>;
    SigningType Type;
};

struct DebugMetadataSection  // subclass of ImageMetadataSection
{
    UINT32 BuildDateLow <format=hex>;
    UINT32 BuildDateHigh <format=hex>;
    CHAR Name[32];
    // Methods omitted.
};

struct MetadataIdentity
{
    UINT32 Version;
    IdentityType Type;
};

struct ABIProvidesMetadataSection
{
    UINT32 VersionCount;
    MetadataIdentity Versions[VersionCount];
};

struct ABIDependsMetadataSection
{
    UINT32 VersionCount;
    MetadataIdentity Versions[VersionCount];
};

struct RevocationMetadataSection
{
    UINT32 SecurityVersionNumber;
};

int64 FindLast(UINT32 value)
{
    local TFindResults results = FindAll(value);

    return results.start[results.count - 1];
}


// Parsing.

FSeek(FindLast(expected_magic));  // find magic

// XXX: There's also 'ParseLegacyMetadata'.
ImageMetadataHeader hdr;

local int section_index;
for (section_index = 0; section_index < hdr.SectionCount; ++section_index) {
    ImageMetadataSectionHeader section_hdr;

    if (section_hdr.SectionId == Identity) {
        IdentityMetadataSection identity_section;

    } else if (section_hdr.SectionId == Signature) {
        SignatureMetadataSection signature_section;

    } else if (section_hdr.SectionId == Debug) {
        DebugMetadataSection debug_section;

    } else if (section_hdr.SectionId == ABIProvides) {
        ABIProvidesMetadataSection abi_provides_section;

    } else if (section_hdr.SectionId == ABIDepends) {
        ABIDependsMetadataSection abi_depends_section;

    } else if (section_hdr.SectionId == Revocation) {
        RevocationMetadataSection revocation_section;

    // XXX: Parse more sections here.
    } else {
       Printf("Unknown section: 0x%hx\n", section_hdr.SectionId);
    }
}
```

common.bt:
```c
#ifndef COMMON_H
#define COMMON_H

typedef enum <UINT16>
{
    InvalidImageType = 0,
    OneBL = 1,
    PlutonRuntime = 2,
    WifiFirmware = 3,
    SecurityMonitor = 4,
    NormalWorldLoader = 5,
    NormalWorldDTB = 6,
    NormalWorldKernel = 7,
    RootFs = 8,
    Services = 9,
    Applications = 10, // 0x000A
    FirmwareConfig = 13, // 0x000D
    BootManifest = 16, // 0x0010
    NormalWorldFileSystem = 17, // 0x0011
    TrustedKeystore = 19, // 0x0013
    Policy = 20, // 0x0014
    CustomerBoardConfig = 21, // 0x0015
    UpdateCertStore = 22, // 0x0016
    BaseSystemUpdateManifest = 23, // 0x0017
    FirmwareUpdateManifest = 24, // 0x0018
    CustomerUpdateManifest = 25, // 0x0019
    RecoveryManifest = 26, // 0x001A
    ManifestSet = 27, // 0x001B
    Other = 28, // 0x001C
} ImageType <read=ReadImageType>;

string ReadImageType(ImageType image_type)
{
    local string s;

    switch (image_type) {
        case 0:  s = "invalid image type"; break;
        case 1:  s = "one bl"; break;
        case 2:  s = "pluton runtime"; break;
        case 3:  s = "wi-fi firmware"; break;
        case 4:  s = "security monitor"; break;
        case 5:  s = "normal world loader"; break;
        case 6:  s = "normal world dtb"; break;
        case 7:  s = "normal world kernel"; break;
        case 8:  s = "root fs"; break;
        case 9:  s = "services"; break;
        case 10: s = "applications"; break;
        case 13: s = "firmware config"; break;
        case 16: s = "boot manifest"; break;
        case 17: s = "normal world file system"; break;
        case 19: s = "trusted keystore"; break;
        case 20: s = "policy"; break;
        case 21: s = "customer board config"; break;
        case 22: s = "update cert store"; break;
        case 23: s = "base system update manifest"; break;
        case 24: s = "firmware update manifest"; break;
        case 25: s = "customer update manifest"; break;
        case 26: s = "recovery manifest"; break;
        case 27: s = "manifest set"; break;
        case 28: s = "other"; break;
    }

    return s;
}

typedef enum <UINT32>
{
    IdentityTypeNone,
    SecureWorldRuntime,
    OSRuntime,
    ApplicationRuntime,
} IdentityType <read=ReadIdentityType>;

string ReadIdentityType(IdentityType id_type)
{
    local string s;

    switch (id_type) {
        case 0: s = "none"; break;
        case 1: s = "secure world runtime"; break;
        case 2: s = "OS runtime"; break;
        case 3: s = "application runtime"; break;
    }

    return s;
}

#endif
```

trusted_keystore.bt:
```c
struct TKS_Hdr
{
    UINT16 num_entries;
    UINT16 unk;
};

struct TKS_Entry
{
    // The last 4 bytes: key size, thumbprint size.
    UBYTE hdr[16];
    UBYTE pub_key[64];
    UBYTE thumbprint[20];
};

struct UTBL_Hdr
{
    UINT32 magic;  // UTBL
    UINT32 num_entries;
};

TKS_Hdr hdr;

local int entry_index;
local int hdr_index;
local int hdr_size;
for (entry_index = 0; entry_index < hdr.num_entries; ++entry_index) {
    TKS_Entry entry;

    hdr_size = sizeof(entry.hdr) / sizeof(entry.hdr[0]);

    Printf("hdr:");
    for (hdr_index = 0; hdr_index < hdr_size; ++hdr_index) {
        Printf(" %02x", entry.hdr[hdr_index]);
    }
    Printf("\n");
}

UTBL_Hdr utbl_hdr;

local int utbl_index;
for (utbl_index = 0; utbl_index < utbl_hdr.num_entries; ++utbl_index) {
    UINT32 utbl;
}

#include "image_metadata.bt"
```

## ASXipFS
Azure Sphere eXecute In Place File System (ASXipFS) is based on CRAMFS and designed for read only file systems that use execute in place (XIP) techniques to limit RAM usage on compatible MTD devices.

### Ruby Square
We also built a tool called Ruby Square (as a pun on Azure Sphere) that will unpack
and rename all the files in the ASXIPFS recovery image for you. We also added a packing feature based on earlier research by [Georgi Angelov], so we can deploy our own application package to Azure Sphere by for instance replacing `gdbserver.imagepackage` image in `C:\Program Files (x86)\Microsoft Azure Sphere SDK\DebugTools`.

```bash
./ruby-square.py --help
usage: ruby-square.py [-h] [-g] [-u] [-p] [-i INPUT] [-o OUTPUT]

Ruby Square for Azure Sphere.

optional arguments:
  -h, --help            show this help message and exit
  -g, --godmode         Process a recovery folder
  -u, --unpack          Unpack an Azure ROMFS image
  -p, --pack            Pack an Azure ROMFS image
  -i INPUT, --input INPUT, --input INPUT
                        Input file/directory
  -o OUTPUT, --output OUTPUT, --output OUTPUT
                        Output file/directory
```

Example output:

```bash
d-----        6/30/2020   1:26 PM                3aded48abba146a89898994059afc548_RootFs_Firmware_nw-root-filesystem
d-----        6/30/2020   1:26 PM                59af9abaf46e480caed08cef0aabab58_Services_Firmware_gatewayd
d-----        6/30/2020   1:26 PM                743f011fa0ff4d058719d869991915b1_Services_Firmware_azured
d-----        6/30/2020   1:26 PM                80e6c2a25100416e91a91c195e067f6f_Services_Firmware_azcore
d-----        6/30/2020   1:26 PM                d98ec5f3fafb424e87ee2ed482d1b17d_Services_Firmware_networkd
d-----        6/30/2020   1:26 PM                e3180ce9c9564b54b5a5d9bbd126e184_Services_Firmware_rng-tools
d-----        6/30/2020   1:26 PM                e5a6b6eed0ef432ba24c9e07f4198d30_UpdateCertStore_Firmware_update-cert-store
-a----         6/5/2020   3:39 PM        1577196 3aded48abba146a89898994059afc548_RootFs_Firmware_nw-root-filesystem_.bin
-a----         6/5/2020   3:39 PM          98516 59af9abaf46e480caed08cef0aabab58_Services_Firmware_gatewayd_.bin
-a----         6/5/2020   3:39 PM          65748 743f011fa0ff4d058719d869991915b1_Services_Firmware_azured_.bin
-a----         6/5/2020   3:39 PM          16596 80e6c2a25100416e91a91c195e067f6f_Services_Firmware_azcore_.bin
-a----         6/5/2020   3:39 PM            392 85a5dc4e7ad34cbd8a58912d1b116a8d_BootManifest_Firmware_device-capability_.bin
-a----         6/5/2020   3:39 PM           2376 92854503e1a4425ab9a81f990b6f03bc_TrustedKeystore_Firmware_trusted-keystore_.bin
-a----         6/5/2020   3:39 PM          16932 93d26089b31f47959c42a8caa98b315d_NormalWorldLoader_Firmware_a7-nw-loader_.bin
-a----         6/5/2020   3:39 PM          26860 b8d1898d61d14c7d96ee1c387658f816_PlutonRuntime_Firmware_pluton-runtime_.bin
-a----         6/5/2020   3:39 PM        2491164 bec9744660fd40f7abd8ef396c36e88e_NormalWorldKernel_Firmware_nw-kernel_.bin
-a----         6/5/2020   3:40 PM         114900 d36848d9dad148b8abda510da53bd623_Applications_Firmware_security-monitor_.bin
-a----         6/5/2020   3:40 PM         269980 d77ab2e3bbde4c8fab42821a45b39368_WifiFirmware_Firmware_n9-wifi-firmware_.bin
-a----         6/5/2020   3:40 PM         614620 d98ec5f3fafb424e87ee2ed482d1b17d_Services_Firmware_networkd_.bin
-a----         6/5/2020   3:40 PM           8396 e3180ce9c9564b54b5a5d9bbd126e184_Services_Firmware_rng-tools_.bin
-a----         6/5/2020   3:40 PM          24576 e5a6b6eed0ef432ba24c9e07f4198d30_UpdateCertStore_Firmware_update-cert-store_.bin
-a----         6/5/2020   3:40 PM          16384 e6159560434f47e89376b67d030628f8_OneBL_BootloaderOneBackup_1bl_.bin
-a----         6/5/2020   3:40 PM          29732 e7a7ab1c642e43b996694c29739c5056_NormalWorldDTB_Firmware_nw-device-tree_.bin
-a----         6/5/2020   3:40 PM          16384 recovery-1bl-rtm_recovery-1bl_.bin
-a----         6/5/2020   3:40 PM          60836 recovery-runtime_recovery-rt_.bin
-a----         6/5/2020   3:40 PM           1496 recovery.imagemanifest
```

However, for the recovery process, the files need to have their original names
(as specified in the manifest file).

## More on Recovery

There is also an old format of the recovery files, but those are also signed
and we couldn't load them onto device anyway.  Likely because our boards are too
new and don't support the old format.

Microsoft doesn't allow you to download previous recovery versions, so you
might want to save them locally.

Besides the files themselves, Microsoft also [provides] a [JSON] metadata file
containing all the component and image IDs of firmware components.

```json
{
  "versions": [
    {
      "name": "TP4.1.0.0",
      "images": [
        {
          "cid": "16bf62d0-f47e-11e6-839c-00155d9f1e00",
          "iid": "94966959-6c74-40d0-bbe2-549a6f2bfbde"
        },
        {
          "cid": "32fc880c-f31f-471b-a4b5-91585b66b37e",
          "iid": "87a54c7b-c921-4321-b5f0-718699829f68"
        },
        {
          "cid": "6904e268-2627-5ae4-92f2-96176db30269",
          "iid": "f2e80e0c-70e0-439d-8357-d8b72c87ab4b"
        },
        {
          "cid": "a87d9f43-e240-4dab-8a85-54512ddffe00",
          "iid": "69df1dfd-d744-4f19-8c6e-d1265455c61b"
...
```

In the recovery, there are several types of files:

- data (trusted keystore and image manifest)
- high-level system services running on A7
- security monitor and kernel running on A7
- firmware for the M4 and N9 cores (bootloaders and Pluton).

System services are packed using ASXIPFS, which is a version of CRAMFS without compression.

## Loading the Firmware

The Andes N9 32-bit RISC core used for Wi-Fi we ignored completely.  The rest
of the firmware can be loaded into IDA by selecting the proper processor
module and setting options as follows:

```
Target processor - ARM Little-endian

Processor specific analysis options
-> Edit ARM architecture options

Base architecture
ARMv7-M

Thumb instructions
Thumb-2
```

When disassembling code, the thumb/ARM mode can be configured with `Alt-G`, by
setting the virtual register `T`.

The M4 binaries start with the vector table, which is documented on page 37 of
the [Cortex-M4 Devices Generic User Guide]:

```
ROM:00100000 00 52 10 00 init_sp_value   DCD 0x105200
ROM:00100004 85 04 10 00 reset_vector    DCD start+1
ROM:00100008 23 13 10 00                 DCD sub_101322+1
ROM:0010000C 23 13 10 00                 DCD sub_101322+1
ROM:00100010 23 13 10 00                 DCD sub_101322+1
ROM:00100014 23 13 10 00                 DCD sub_101322+1
ROM:00100018 23 13 10 00                 DCD sub_101322+1
ROM:0010001C 00 00 00 00                 DCD 0
ROM:00100020 00 00 00 00                 DCD 0
ROM:00100024 00 00 00 00                 DCD 0
ROM:00100028 00 00 00 00                 DCD 0
ROM:0010002C 23 13 10 00                 DCD sub_101322+1
ROM:00100030 23 13 10 00                 DCD sub_101322+1
ROM:00100034 00 00 00 00                 DCD 0
ROM:00100038 23 13 10 00                 DCD sub_101322+1
ROM:0010003C 3D 13 10 00                 DCD sub_10133C+1
```

By converting this region to data (DCD), you can guess the load address.  The
reset vector (start) should be within the binary.  After disassembling there,
IDA should figure out most of the things on its own.  But you might need
to disassemble some regions yourself or convert some code to procedures.

The security monitor runs on the A7 core, but it's loaded similarly.
The only difference is that the binary starts with this header:

```
ROM:803D0000 00 00 3D 80 load_addr       DCD 0x803D0000
ROM:803D0004 A4 91 01 00 image_size      DCD 0x191A4
ROM:803D0008 3D 55 3D 80 start_addr      DCD 0x803D553D
```

Note the +1 in the above addresses.  This is just to indicate that the thumb
mode is used and is ignored by the processor.  So the actual code address is at
-1.

After this, you can start reverse engineering.  Look at the strings, identify
common functions like `memset`, search for constants, etc.

## Third-party Code and Diffing

Besides the recovery files, you can take advantage of the fact that Microsoft
uses third-party code which requires them to release the source, including the
custom Linux kernel.  It can be found [here] by filtering for "azure
sphere".

[Beyond Compare] can be used to diff the sources.

You can also use a script like the following to remove any extraneous files
from the tree.

remove_not_azure.sh:
```bash
#!/usr/bin/env bash

set -euxo pipefail

# Remove every file NOT matching a pattern.
#
# Make sure the enclosing directory doesn't contain these patterns, or
# everything will be kept as is.
#
# Only files are removed to avoid removing a directory first before inspecting
# the files inside.

DIR="$1"

find "$DIR" -type f -not \( \
    -wholename "*azspio*"  -o \
    -wholename "*azure*"   -o \
    -wholename "*sphere*"  -o \
    -wholename "*pluton*"  -o \
    -wholename "*mt3620*"  -o \
    -wholename "*asxipfs*" -o \
    -wholename "*littlefs*" \
    \) \
    -delete
```

Run `remove_not_azure.sh` on the kernel tree (see the comments in the
script) and generate reports in Beyond Compare for all subsequent versions:

- Edit -> Expand All
- Edit -> Select All Files
- Actions -> File Compare Report...
- Select HTML report and save.

Note that the Azure Sphere ioctls and related code changed in 20.07, making it
more generic and harder to analyze.  So you might want to look at earlier
kernels for the previous struct definitions.  There were no significant changes
between 20.04 and 20.06 while the team migrated to a new kernel version.

In general, you want to look at all kernel versions to avoid missing something.
You can find things like the default config in `Azure Sphere_20.04_Linux
kernel/linux/arch/arm/configs/mt3620_defconfig`.  Or the device tree in
`Azure Sphere_19.07_Linux kernel/linux/arch/arm/boot/dts/mt3620.dtsi`.

The former would be useful if you wanted to build a kernel fuzzer.  A lot of
options are disabled due to security and [size constraints].  The latter is
useful for reverse engineering.  You might also find some testing tools
used by the kernel team.

For diffing the binaries, you can use 010 Editor (Tools -> Compare Files), but
it often produces confusing output, which requires having a disassembler
opened next to it to verify the results.

For IDA, [Diaphora] is useful, but you probably should name similar functions
manually before diffing since this produces the best results.

## System Services

Here is the filesystem tree extracted from the 20.04 recovery image:

```
├── 4eae96aee7b646e5b46c67f5d1e0b9de_azcore
│   ├── app_manifest.json
│   └── bin
│       └── azcore
├── 6e60c23549f24b36b86e953b19531c14_rng-tools
│   └── app_manifest.json
├── 7906071bd15d480895dd894b313ed1d4_azured
│   ├── app_manifest.json
│   └── bin
│       └── azured
├── a2cc820e30aa4a1caa36942fb5e720df_gatewayd
│   ├── app_manifest.json
│   └── bin
│       ├── gatewayd
│       ├── gatewayd-server-cert.pem
│       └── gatewayd-server-key.pem
├── c618bd1641d2416094cf8b26d1b0d7c5_networkd
│   ├── app_manifest.json
│   └── bin
│       ├── networkd
│       ├── wpa_supplicant
│       └── wpa_supplicant.conf
├── de314960756447afa6a3cf8df7415b4d_nw_root_filesystem
│   ├── dev
│   ├── etc
│   │   ├── fstab
│   │   ├── group
│   │   ├── hosts
│   │   ├── libnl
│   │   │   ├── classid
│   │   │   └── pktloc
│   │   └── passwd
│   ├── lib
│   │   └── libgcc_s.so.1
│   ├── mnt
│   │   ├── apps
│   │   ├── cgroup
│   │   ├── config
│   │   ├── sys
│   │   └── update-cert-store
│   ├── proc
│   ├── run
│   ├── usr
│   │   ├── bin
│   │   │   └── application-manager
│   │   └── lib
│   │       ├── libapplibs.so.0.1
│   │       ├── libazureiot.so.1
│   │       ├── libc++runtime.so.1
│   │       ├── libc.so
│   │       ├── libcurl.so.4.5.0
│   │       ├── libdps-custom-hsm.so.0
│   │       ├── libnl-3.so.200.26.0
│   │       ├── libnl-genl-3.so.200.26.0
│   │       ├── libtlsutils.so.0
│   │       └── libwolfssl.so.15.0.0
│   └── var
│       └── volatile
│           └── tmp
└── e5a6b6eed0ef432ba24c9e07f4198d30_update-cert-store
    └── certs
        └── BaltimoreCyberTrustRoot.pem
```

The binaries are just ELF 32-bit shared objects.  The names of the services are
mostly self-explanatory.

We didn't look much into these, but `application-manager` is the init system,
it mounts the ASXIPFS and littlefs filesystems (search for `mount` in IDA).

ASXIPFS is what the user apps use.  This filesystem includes the ability to set
setuid/setgid bits, but these are stripped for user apps.  There was also
support for special device files, which was used by Talos to [escalate
privileges] by flashing a special image package.

`gatewayd` handles HTTP requests sent to the device.

From the 20.04 recovery:

```
.data.rel.ro:000222D8 http_routes     http_route <aAppStatus, GET, http_app_status_get+1, \
.data.rel.ro:000222D8                             azsphere_capabilities+1> ; "/app/status"
.data.rel.ro:000222E8                 http_route <aNetInterfaces, GET, http_net_interface_get+1, \ ; "/net/interfaces"
.data.rel.ro:000222E8                             azsphere_capabilities+1>
.data.rel.ro:000222F8                 http_route <aRestart, POST, http_restart_post+1, \ ; "/restart"
.data.rel.ro:000222F8                             azsphere_capabilities+1>
.data.rel.ro:00022308                 http_route <aDeviceManufact, GET, \ ; "/device/manufacturing_state"
.data.rel.ro:00022308                             http_device_manufacturing_state_get+1, 0>
.data.rel.ro:00022318                 http_route <aLog, GET, http_log_get+1, azsphere_capabilities+1> ; "/log"
.data.rel.ro:00022328                 http_route <aWifiConfigNetw, PATCH, http_wifi_config_networks_patch+1,\ ; "/wifi/config/networks"
.data.rel.ro:00022328                             azsphere_capabilities+1>
.data.rel.ro:00022338                 http_route <aWifiConfigNetw, POST, http_wifi_config_networks_post+1, \ ; "/wifi/config/networks"
.data.rel.ro:00022338                             azsphere_capabilities+1>
.data.rel.ro:00022348                 http_route <aAbiVersions, GET, http_abi_versions_get+1, 0> ; "/abi_versions"
.data.rel.ro:00022358                 http_route <aCertstoreSpace, GET, http_certstore_space_get+1, \ ; "/certstore/space"
.data.rel.ro:00022358                             azsphere_capabilities+1>
.data.rel.ro:00022368                 http_route <aWifiConfigNetw, GET, http_wifi_config_networks_get+1, \ ; "/wifi/config/networks"
.data.rel.ro:00022368                             azsphere_capabilities+1>
.data.rel.ro:00022378                 http_route <aTelemetry_0, GET, http_telemetry_get+1, \ ; "/telemetry"
.data.rel.ro:00022378                             azsphere_capabilities+1>
.data.rel.ro:00022388                 http_route <aCertstoreCerts, POST, http_certstore_certs_post+1, \ ; "/certstore/certs"
.data.rel.ro:00022388                             azsphere_capabilities+1>
.data.rel.ro:00022398                 http_route <aWifiDiagnostic, GET, \ ; "/wifi/diagnostics/networks"
.data.rel.ro:00022398                             http_wifi_diagnostics_networks_get+1, \
.data.rel.ro:00022398                             azsphere_capabilities+1>
.data.rel.ro:000223A8                 http_route <aUpdateInstall, POST, http_update_install_post+1, \ ; "/update/install"
.data.rel.ro:000223A8                             azsphere_capabilities+1>
.data.rel.ro:000223B8                 http_route <aWifiInterface, PATCH, http_wifi_interface_patch+1, \ ; "/wifi/interface"
.data.rel.ro:000223B8                             azsphere_capabilities+1>
.data.rel.ro:000223C8                 http_route <aImages, GET, http_images_get+1, azsphere_capabilities+1> ; "/images"
.data.rel.ro:000223D8                 http_route <aNetStatus, GET, http_net_status_get+1, 0> ; "/net/status"
.data.rel.ro:000223E8                 http_route <aAppImage, DELETE, http_app_image_delete+1, \ ; "/app/image"
.data.rel.ro:000223E8                             azsphere_capabilities+1>
.data.rel.ro:000223F8                 http_route <aDeviceCapabili_0, GET, http_device_capabilities_get+1, 0> ; "/device/capabilities"
.data.rel.ro:00022408                 http_route <aAppQuota, GET, http_app_quota_get+1, \ ; "/app/quota"
.data.rel.ro:00022408                             azsphere_capabilities+1>
.data.rel.ro:00022418                 http_route <aAppStatus, PATCH, http_app_status_patch+1, \ ; "/app/status"
.data.rel.ro:00022418                             azsphere_capabilities+1>
.data.rel.ro:00022428                 http_route <aDeviceManufact, PUT, http_get_manufacturing_state_put+1, \ ; "/device/manufacturing_state"
.data.rel.ro:00022428                             azsphere_capabilities+1>
.data.rel.ro:00022438                 http_route <aCertstoreCerts, GET, http_certstore_certs_get+1, \ ; "/certstore/certs"
.data.rel.ro:00022438                             azsphere_capabilities+1>
.data.rel.ro:00022448                 http_route <aWifiConfigNetw, DELETE, \ ; "/wifi/config/networks"
.data.rel.ro:00022448                             http_wifi_config_networks_delete+1, \
.data.rel.ro:00022448                             azsphere_capabilities+1>
.data.rel.ro:00022458                 http_route <aTelemetry_0, DELETE, http_telemetry_delete+1, \ ; "/telemetry"
.data.rel.ro:00022458                             azsphere_capabilities+1>
.data.rel.ro:00022468                 http_route <aAppStatus+4, GET, http_uptime_get+1, 0> ; "/status"
.data.rel.ro:00022478                 http_route <aWifiInterface, GET, http_wifi_interface_get+1, \ ; "/wifi/interface"
.data.rel.ro:00022478                             azsphere_capabilities+1>
.data.rel.ro:00022488                 http_route <aUpdateStage, PUT, http_update_stage_put+1, \ ; "/update/stage"
.data.rel.ro:00022488                             azsphere_capabilities+1>
.data.rel.ro:00022498                 http_route <aCertstoreCerts, DELETE, http_certstore_certs_delete+1, \ ; "/certstore/certs"
.data.rel.ro:00022498                             azsphere_capabilities+1>
.data.rel.ro:000224A8                 http_route <aWifiScan, GET, http_wifi_scan_get+1, \ ; "/wifi/scan"
.data.rel.ro:000224A8                             azsphere_capabilities+1>
.data.rel.ro:000224B8                 http_route <aDeviceSecurity, GET, http_device_security_state_get+1, 0> ; "/device/security_state"
```

The format is as follows:

- HTTP route string pointer
- type enum (GET, POST, etc.)
- function handler pointer (different for different types)
- seems like permission checking based on the device capabilities file.

Types:

```
0 - GET
1 - POST
2 - PUT
3 - DELETE
4 - PATCH
```

Some example HTTP routes:

```
GET https://192.168.35.2/abi_versions
GET https://192.168.35.2/app/status/d3b80666-feaf-433a-b294-6a5846853b4a
GET https://192.168.35.2/device/capabilities
GET https://192.168.35.2/device/manufacturing_state
GET https://192.168.35.2/device/security_state
GET https://192.168.35.2/images
GET https://192.168.35.2/status
GET https://192.168.35.2/wifi/interface

POST https://192.168.35.2/update/install

PUT https://192.168.35.2/update/stage

PATCH https://192.168.35.2/app/status/1689d8b2-c835-2e27-27ad-e894d6d15fa9
PATCH https://192.168.35.2/app/status/16bf62d0-f47e-11e6-839c-00155d9f1e00
PATCH https://192.168.35.2/app/status/d3b80666-feaf-433a-b294-6a5846853b4a

DELETE https://192.168.35.2/app/image/1689d8b2-c835-2e27-27ad-e894d6d15fa9
DELETE https://192.168.35.2/app/image/d3b80666-feaf-433a-b294-6a5846853b4a
```

By looking at the system services, you can also learn how they communicate with
privileged components such as Pluton and the security monitor (search for `ioctl`).

In 20.04, the devices are exposed via these paths:

```
.rodata:0000F219 aDevSecurityMon DCB "/dev/security-monitor",0
.rodata:0000F22F aDevPluton      DCB "/dev/pluton",0
```

## Patching the libc

(This is based on earlier research by [Georgi Angelov].)

You can change the provided libc slightly to give you more freedom to explore
the device.

In the following example, we have to use version 3 in version 5.  Since it's a
stub, it may not matter, but it might cause issues.  For some reason, the
original `ld-musl-armhf.so.1` was only present in version 3.

- Open the `C:\Program Files (x86)\Microsoft Azure Sphere SDK\Sysroots\3\lib`
  folder.

- Copy `ld-musl-armhf.so.1` (18 September 2019) to `C:\Program Files
  (x86)\Microsoft Azure Sphere SDK\Sysroots\5\usr\lib` (other libraries are from
  2 April 2020).

- In the folder `C:\Program Files (x86)\Microsoft Azure Sphere
  SDK\Sysroots\5\usr\lib`, rename `libc.so` into `_libc.so` (backup).

- Still in the folder `C:\Program Files (x86)\Microsoft Azure Sphere
  SDK\Sysroots\5\usr\lib`, rename `ld-musl-armhf.so.1` into `libc.so`.

Open an existing application such as [`HelloWorld_HighLevelApp`] and modify it to
try to read meminfo.  Note that we do need to declare any missing functions such
as open, close, read, etc.

```c
int open(const char *, int, ...);
int close(int);
int read(int, void *, size_t);

void
ReadDevice(const char *deviceName) {
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    int fd = open(deviceName, 0); // do not write, FS is read only
    Log_Debug("DBG: open(\"%s\") => %d\n", deviceName, fd);
    if (fd != -1) {
        read(fd, buf, sizeof(buf));
        Log_Debug("%.*s", sizeof(buf), buf);
        close(fd);
    } else {
        Log_Debug("ERR: open(\"%s\") is not permitted.\n", deviceName);
    }
}

int main(void)
{
    Log_Debug("\n[?] CPU Information...\n");
    ReadDevice("/proc/cpuinfo");
    Log_Debug("\n[?] Memory Information...\n");
    ReadDevice("/proc/meminfo");
    Log_Debug("\n[?] KCore Information...\n");
    ReadDevice("/proc/kcore");
    Log_Debug("\n[?] IOMem Information...\n");
    ReadDevice("/proc/iomem");
    Log_Debug("\n[?] kallsyms Information...\n");
    ReadDevice("/proc/kallsyms");
}
```

Output:

```
[?] CPU Information...
DBG: open("/proc/cpuinfo") => 3
processor	: 0
model name	: ARMv7 Processor rev 3 (v7l)
BogoMIPS	: 52.00
Features	: half thumb fastmult vfp edsp thumbee neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm 
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x0
CPU part	: 0xc07
CPU revision	: 3

Hardware	: MediaTek MT3620
Revision	: 0000
Serial		: 0000000000000000

[?] Memory Information...
DBG: open("/proc/meminfo") => 3
MemTotal:           3472 kB
MemFree:             772 kB
MemAvailable:       1044 kB
Buffers:               0 kB
Cached:              216 kB
SwapCached:            0 kB
Active:              684 kB
Inactive:             64 kB
Active(anon):        532 kB
Inactive(anon):        0 kB
Active(file):        152 kB
Inactive(file):       64 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                 0 kB
Writeback:             0 kB
AnonPages:           532 kB
Mapped:                0 kB
Shmem:                 0 kB
Slab:               1316 kB
SReclaimable:        168 kB
SUnreclaim:         1148 kB
KernelStack:         128 kB
PageTables:           68 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:        1736 kB
Committed_AS:       1560 kB
VmallocTotal:    1032192 kB
VmallocUsed:           0 kB
VmallocChunk:          0 kB

[?] KCore Information...
DBG: open("/proc/kcore") => -1
ERR: open("/proc/kcore") is not permitted.

[?] IOMem Information...
DBG: open("/proc/iomem") => -1
ERR: open("/proc/iomem") is not permitted.

[?] kallsyms Information...
DBG: open("/proc/kallsyms") => -1
ERR: open("/proc/kallsyms") is not permitted.
```

You can call any interesting ioctls this way too (assuming you have the right
permissions -- see the Linux source).

From 20.04:

```c
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <applibs/log.h>
#include <hw/sample_hardware.h>

int open(const char *, int, ...);
int close(int);
int read(int, void *, size_t);
int ioctl(int fildes, unsigned long request, ...);

#define PLUTON_GET_ENABLED_CAPABILITIES 0x8080700E

/// <summary>
/// Message used for getting enabled capabilities from M4
/// </summary>
struct azure_sphere_get_enabled_capabilities {
    /// <summary>
    /// Input data: the capability to be checked
    /// </summary>
    uint16_t o_enabled_capabilities[64];
};

int main(void)
{
    int fd;
    int res;
    struct azure_sphere_get_enabled_capabilities out;
    memset(&out, 0, sizeof(out));

    fd = open("/dev/pluton", 0);
    Log_Debug("DBG: pluton fd: %d\n", fd);

    res = ioctl(fd, PLUTON_GET_ENABLED_CAPABILITIES, &out);
    Log_Debug("DBG: ioctl res: %d\n", res);

    for (int i = 0; i < 64; ++i) {
        Log_Debug("DBG: o_enabled_capabilities[%02x]: %04x\n",
            i, out.o_enabled_capabilities[i]);
    }
}
```

Output:

```
DBG: pluton fd: 3
DBG: ioctl res: 0
DBG: o_enabled_capabilities[00]: 000b
DBG: o_enabled_capabilities[01]: 000c
DBG: o_enabled_capabilities[02]: 0000
DBG: o_enabled_capabilities[03]: 0000
DBG: o_enabled_capabilities[04]: 0000
...
DBG: o_enabled_capabilities[3f]: 0000
```

## Pluton Subsystem
### IOCTLs
(The following assumes the 20.04 recovery.)

Pluton is the security subsystem of the device.  Looking at the kernel source,
the following ioctl functions were identified:

index | name                                    | capability required?
------|-----------------------------------------|---------------------------------------
0x2   | PLUTON_SET_POSTCODE                     | AZURE_SPHERE_CAP_POSTCODE
0x3   | PLUTON_GET_BOOT_MODE_FLAGS              | no
0x41  | PLUTON_GET_SECURITY_STATE               | no
0x48  | PLUTON_IS_CAPABILITY_ENABLED            | no
0x49  | PLUTON_GET_ENABLED_CAPABILITIES         | no
0x51  | PLUTON_GET_MANUFACTURING_STATE          | AZURE_SPHERE_CAP_UPDATE_SECURITY_STATE
0x52  | PLUTON_SET_MANUFACTURING_STATE          | AZURE_SPHERE_CAP_UPDATE_SECURITY_STATE
0x4a  | PLUTON_GENERATE_CLIENT_AUTH_KEY         | AZURE_SPHERE_CAP_ATTESTATION_RUNTIME
0x4e  | PLUTON_COMMIT_CLIENT_AUTH_KEY           | AZURE_SPHERE_CAP_ATTESTATION_RUNTIME
0x4b  | PLUTON_GET_TENANT_PUBLIC_KEY            | no
0x4c  | PLUTON_PROCESS_ATTESTATION              | AZURE_SPHERE_CAP_ATTESTATION_RUNTIME
0x4d  | PLUTON_SIGN_WITH_TENANT_ATTESTATION_KEY | no
0x56  | PLUTON_DECODE_CAPABILITIES              | no


Then the handler table was found in the firmware code.  This is easy to do by looking
through the data region and checking if anything looks like structured data.

```
ROM:0010DC28 02 00 00 00+PlutonCommandTable PLUTON_COMMAND_ENTRY <2, RemoteApi, PlRApiSetPostcode+1, 0>
ROM:0010DC38 03 00 00 00+                PLUTON_COMMAND_ENTRY <3, RemoteApi, PlRApiGetBootModeFlags+1, 0>
ROM:0010DC48 50 00 00 00+                PLUTON_COMMAND_ENTRY <0x50, Internal, PlRApiDeviceReset+1, 0>
ROM:0010DC58 40 00 00 00+                PLUTON_COMMAND_ENTRY <0x40, RemoteApi, PlRApiReadRng+1, 0>
ROM:0010DC68 30 00 00 00+                PLUTON_COMMAND_ENTRY <0x30, Internal, PlpCommandIndex_48+1, 0>
ROM:0010DC78 31 00 00 00+                PLUTON_COMMAND_ENTRY <0x31, Internal, PlpCommandIndex_49+1, 0>
ROM:0010DC88 32 00 00 00+                PLUTON_COMMAND_ENTRY <0x32, Internal, PlpCommandIndex_50+1, 0>
ROM:0010DC98 33 00 00 00+                PLUTON_COMMAND_ENTRY <0x33, Internal, PlpCommandIndex_51+1, 0>
ROM:0010DCA8 34 00 00 00+                PLUTON_COMMAND_ENTRY <0x34, Internal, PlpCommandIndex_52+1, 0>
ROM:0010DCB8 35 00 00 00+                PLUTON_COMMAND_ENTRY <0x35, Internal, PlpCommandIndex_53+1, 0>
ROM:0010DCC8 36 00 00 00+                PLUTON_COMMAND_ENTRY <0x36, Internal, PlpCommandIndex_54+1, 0>
ROM:0010DCD8 37 00 00 00+                PLUTON_COMMAND_ENTRY <0x37, Internal, PlpCommandIndex_55+1, 0>
ROM:0010DCE8 38 00 00 00+                PLUTON_COMMAND_ENTRY <0x38, Internal, PlpCommandIndex_56+1, 0>
ROM:0010DCF8 39 00 00 00+                PLUTON_COMMAND_ENTRY <0x39, Internal, PlpCommandIndex_57+1, 0>
ROM:0010DD08 3A 00 00 00+                PLUTON_COMMAND_ENTRY <0x3A, Internal, PlpCommandIndex_58+1, 0>
ROM:0010DD18 41 00 00 00+                PLUTON_COMMAND_ENTRY <0x41, RemoteApi, PlRApiGetSecurityState+1, 0>
ROM:0010DD28 42 00 00 00+                PLUTON_COMMAND_ENTRY <0x42, Internal, PlpCommandIndex_66+1, 0> ; VerifyImageRequest?
ROM:0010DD38 48 00 00 00+                PLUTON_COMMAND_ENTRY <0x48, RemoteApi, PlRApiIsCapabilityEnabled+1, 0>
ROM:0010DD48 49 00 00 00+                PLUTON_COMMAND_ENTRY <0x49, RemoteApi, PlRApiGetEnabledCapabilities+1,\
ROM:0010DD48 06 00 00 00+                                      0>
ROM:0010DD58 51 00 00 00+                PLUTON_COMMAND_ENTRY <0x51, RemoteApi, PlRApiGetManufacturingState+1, \
ROM:0010DD58 06 00 00 00+                                      0>
ROM:0010DD68 52 00 00 00+                PLUTON_COMMAND_ENTRY <0x52, RemoteApi, PlRApiSetManufacturingState+1, \
ROM:0010DD68 06 00 00 00+                                      0>
ROM:0010DD78 4A 00 00 00+                PLUTON_COMMAND_ENTRY <0x4A, RemoteApi, PlRApiGenerateClientAuthKey+1, \
ROM:0010DD78 06 00 00 00+                                      0>
ROM:0010DD88 4E 00 00 00+                PLUTON_COMMAND_ENTRY <0x4E, RemoteApi, PlRApiCommitClientAuthKey+1, 0>
ROM:0010DD98 4B 00 00 00+                PLUTON_COMMAND_ENTRY <0x4B, RemoteApi, PlRApiGetTenantPublicKey+1, 0>
ROM:0010DDA8 4C 00 00 00+                PLUTON_COMMAND_ENTRY <0x4C, RemoteApi, PlRApiProcessAttestation+1, 0>
ROM:0010DDB8 4D 00 00 00+                PLUTON_COMMAND_ENTRY <0x4D, RemoteApi, \
ROM:0010DDB8 06 00 00 00+                                      PlRApiSignWithTenantAttestationKey+1, 0>
ROM:0010DDC8 04 00 00 00+                PLUTON_COMMAND_ENTRY <4, Internal, PlpCommandIndex_4+1, 0>
ROM:0010DDD8 53 00 00 00+                PLUTON_COMMAND_ENTRY <0x53, Internal, PlpCommandIndex_83+1, 0>
ROM:0010DDE8 54 00 00 00+                PLUTON_COMMAND_ENTRY <0x54, Internal, PlpCommandIndex_84+1, 0>
ROM:0010DDF8 55 00 00 00+                PLUTON_COMMAND_ENTRY <0x55, Internal, PlpCommandIndex_85+1, 0> ; power management? (includes power down)
ROM:0010DE08 56 00 00 00+                PLUTON_COMMAND_ENTRY <0x56, RemoteApi, PlRApiDecodeCapabilities+1, 0>
```

Definitions:

```c
enum PLUTON_COMMAND_TYPE
{
  Internal = 0x2,
  RemoteApi = 0x6,
};

struct PLUTON_COMMAND_ENTRY
{
  int Index;
  PLUTON_COMMAND_TYPE Flags;
  void *Function;
  int u0C;
};
```

### PLUTON_DECODE_CAPABILITIES
After calling some of these with a patched libc to confirm that this code is
reachable at all, we focused our attention on `PLUTON_DECODE_CAPABILITIES`.

This handler is

- reachable by default (no capability check)
- processes user-supplied data
- has an interesting name, likely being responsible for updating the
  device capabilities
- large enough on the firmware side, has interesting functions
  such as `memset` and `memcpy`.

An example capabilities file is shown below:

```
00000000: fd5c fd5c 0100 0000 cc00 0000 006f e629  .\.\.........o.)
00000010: beb6 9fc3 bb06 cf84 94cc c254 61f5 97aa  ...........Ta...
00000020: e076 aa0d 1f9b 4965 6d60 b635 57be cad6  .v....Iem`.5W...
00000030: 5b33 8a1a 5b41 04f7 6964 9aaa 3534 0eca  [3..[A..id..54..
00000040: 1f18 99df 6103 0550 6cd7 bee8 0b00 0000  ....a..Pl.......
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0000 0000 3458 344d  ............4X4M
000000d0: 0300 0000 4944 2400 0d00 0000 d8b5 2841  ....ID$.......(A
000000e0: c2ab 5541 9a33 8a1f 31ed 67ec 715c 5277  ..UA.3..1.g.q\Rw
000000f0: 3ec5 ac4d 9880 df8d 6f3f d761 5347 1800  >..M....o?.aSG..
00000100: 48a8 0ed9 6d26 18d6 083e 5a66 04d9 63b2  H...m&...>Zf..c.
00000110: 58e4 86ae 0100 0000 4442 2800 74b5 f55e  X.......DB(.t..^
00000120: 0000 0000 6677 5f63 6f6e 6669 6700 0000  ....fw_config...
00000130: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000140: 0000 0000 7c00 0000 01cf 4273 771b 1560  ....|.....Bsw..`
00000150: e940 fb95 09f1 14f0 02c9 c4f2 9648 bf79  .@...........H.y
00000160: fd87 03ad fd77 4bda 530e 0a28 78c5 7a97  .....wK.S..(x.z.
00000170: e9e9 a5d8 7a53 6f9c d4bc 6397 098b 673f  ....zSo...c...g?
00000180: d611 791f 75c3 bff0                      ..y.u...
```

The format is as follows:

- fd5c fd5c -- magic
- 0100 0000 -- likely version
- cc00 0000 -- offset
- 006f ... bee8 -- device id
- 0b00 -- (u16) app development capability
- 3458 344d -- start of the metadata.

The capabilities can be specified in any order and can't be 0 (ignored).
The file ends with the metadata size and the ECDSA signature.

An example ioctl call looks like this:

```c
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <applibs/log.h>
#include <hw/sample_hardware.h>

int open(const char *, int, ...);
int close(int);
int read(int, void *, size_t);
int ioctl(int fildes, unsigned long request, ...);

#define PLUTON_DECODE_CAPABILITIES 0x84887011

/// <summary>
/// Message used for decoding a capability blob
/// </summary>
struct azure_sphere_decode_capabilities_request {
	uint32_t length;
	uint8_t capability_blob[1024];
};

struct azure_sphere_decode_capabilities_result {
	/// <summary>
	/// Input data: the capability to be checked
	/// </summary>
	uint16_t enabled_capabilities[64];
	bool success;
};

struct azure_sphere_decode_capabilities_command {
	// Input data
	struct azure_sphere_decode_capabilities_request request;
	// Output data
	struct azure_sphere_decode_capabilities_result result;
};

int main(void)
{
    int fd;
    int res;
    struct azure_sphere_decode_capabilities_command in_out;
    memset(&in_out, 0, sizeof(in_out));

    fd = open("/dev/pluton", 0);
    Log_Debug("DBG: pluton fd: %d\n", fd);

    in_out.request.length = 0x188;
    uint8_t buf[] =
        "\xfd\x5c\xfd\x5c\x01\x00\x00\x00\xcc\x00\x00\x00\x00\x6f\xe6\x29"
        "\xbe\xb6\x9f\xc3\xbb\x06\xcf\x84\x94\xcc\xc2\x54\x61\xf5\x97\xaa"
        "\xe0\x76\xaa\x0d\x1f\x9b\x49\x65\x6d\x60\xb6\x35\x57\xbe\xca\xd6"
        "\x5b\x33\x8a\x1a\x5b\x41\x04\xf7\x69\x64\x9a\xaa\x35\x34\x0e\xca"
        "\x1f\x18\x99\xdf\x61\x03\x05\x50\x6c\xd7\xbe\xe8\x0b\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x58\x34\x4d"
        "\x03\x00\x00\x00\x49\x44\x24\x00\x0d\x00\x00\x00\xd8\xb5\x28\x41"
        "\xc2\xab\x55\x41\x9a\x33\x8a\x1f\x31\xed\x67\xec\x71\x5c\x52\x77"
        "\x3e\xc5\xac\x4d\x98\x80\xdf\x8d\x6f\x3f\xd7\x61\x53\x47\x18\x00"
        "\x48\xa8\x0e\xd9\x6d\x26\x18\xd6\x08\x3e\x5a\x66\x04\xd9\x63\xb2"
        "\x58\xe4\x86\xae\x01\x00\x00\x00\x44\x42\x28\x00\x74\xb5\xf5\x5e"
        "\x00\x00\x00\x00\x66\x77\x5f\x63\x6f\x6e\x66\x69\x67\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x7c\x00\x00\x00\x01\xcf\x42\x73\x77\x1b\x15\x60"
        "\xe9\x40\xfb\x95\x09\xf1\x14\xf0\x02\xc9\xc4\xf2\x96\x48\xbf\x79"
        "\xfd\x87\x03\xad\xfd\x77\x4b\xda\x53\x0e\x0a\x28\x78\xc5\x7a\x97"
        "\xe9\xe9\xa5\xd8\x7a\x53\x6f\x9c\xd4\xbc\x63\x97\x09\x8b\x67\x3f"
        "\xd6\x11\x79\x1f\x75\xc3\xbf\xf0";

    memcpy(in_out.request.capability_blob, buf, in_out.request.length);

    res = ioctl(fd, PLUTON_DECODE_CAPABILITIES, &in_out);
    Log_Debug("DBG: ioctl res: %d\n", res);

    Log_Debug("DBG: success: %d\n", in_out.result.success);

    for (int i = 0; i < 64; ++i) {
        Log_Debug("DBG: enabled_capabilities[%02x]: %04x\n",
            i, in_out.result.enabled_capabilities[i]);
    }
}
```

Output:

```
DBG: pluton fd: 3
DBG: ioctl res: 0
DBG: success: 1
DBG: enabled_capabilities[00]: 000b
DBG: enabled_capabilities[01]: 0000
DBG: enabled_capabilities[02]: 0000
DBG: enabled_capabilities[03]: 0000
...
DBG: enabled_capabilities[3f]: 0000
```

### Emulation

There was an excellent presentation by Quarkslab on attacking [Samsung]
[TrustZone] a while ago.  One of the things they did was emulating the firmware
with [Unicorn].  Naturally, we decided to do the same.

By looking at the xrefs to the handler table, we found the dispatcher
and decided to emulate from there.  There was just no time to properly learn
how shared memory/mailbox works.  By checking the structs in the kernel and
experimenting with simpler ioctls, we managed to get something that
looked good enough.  That is, our code didn't end up in the panic handler.

Also, we separately tracked read and write accesses to learn more about the
accessed memory since Unicorn/the OS allocates memory in pages.

```python
# Handler name and input -> accessed addresses.
HANDLER_ACCESSES = {
    # First random input with matching size.
    AccessKey(
        name="PlRApiSetPostcode",
        input=b"\x08\x00\x41\x42\x43\x44\x45\x46\x47\x48"):
    [
        # Used by PlRApiSetPostcode at 0x00000b16 0x00108b16.
        Access(addr=0x0011ffe8, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe0, type=AccessType(UC_MEM_WRITE), size=4),
...
```

In addition to that, we dumped the execution trace with register context
to a file in CSV:

```
# input file: ../../../re/recovery/09a87fd5eea743799cf162994e0b1958_pluton_runtime.bin
# input buffer: 08004142434445464748
# load address: 0x00108000
0x0010bd44 ; cpsr = 0x400001f3 ; lr   = 0x00000000 ; sp   = 0xfffffffc ; r0   = 0x00000000 ; r1   = 0x00000002 ; r2   = 0x00000002 ; r3   = 0x00001000 ; r4   = 0x00000000 ; r5   = 0x00000000 ; r6   = 0x00000000 ; r7   = 0x00000000 ; r8   = 0x00000000 ; r9   = 0x00000000 ; r10  = 0x00000000 ; r11  = 0x00000000 ; r12  = 0x00000000
0x0010bd46 ; cpsr = 0x400001f3 ; lr   = 0x00000000 ; sp   = 0xffffffe4 ; r0   = 0x00000000 ; r1   = 0x00000002 ; r2   = 0x00000002 ; r3   = 0x00001000 ; r4   = 0x00000000 ; r5   = 0x00000000 ; r6   = 0x00000000 ; r7   = 0x00000000 ; r8   = 0x00000000 ; r9   = 0x00000000 ; r10  = 0x00000000 ; r11  = 0x00000000 ; r12  = 0x00000000
...
```

This allowed as to use this information in IDA to highlight the visited branches
and walk the traces back and forth with VIM-like shortcuts.

ida_highlight.py:
```python
from idaapi import *
from idc import *

def main():
    highlight = AskLong(0, "Choose action: 0 = clear, 1 = highlight")

    if not highlight in [0, 1]:
        Warning("Invalid action: {}".format(highlight))
        return

    color = 0xff0000 if highlight == 1 else 0xffffff

    if highlight == 1:
        trace_file = AskFile(0, "*.txt", "Select trace file")
        if not trace_file:
            Warning("Failed to select trace file")
            return

        with open(trace_file) as lines:
            print "Highlighting..."
            for line in lines:
                line = line.strip()

                # Skip the comments.
                if line.startswith("#"):
                    continue

                split = line.split(" ; ")
                addr = int(split[0], 16)
                idc.SetColor(addr, idc.CIC_ITEM, color)
            print "Done"

    else:
        print "Clearing..."
        addr = 0
        while addr != 0xffffffff:
            idc.SetColor(addr, idc.CIC_ITEM, color)
            addr = next_addr(addr)
        print "Done"

main()
```

ida_navigate.py:
```python
from idaapi import *
from idc import *
import collections

INDEX = 0
ADDRS = []
ADDRS_MAP = {}  # mapping from address to index(es) in 'ADDRS'

Context = collections.namedtuple('Context', 'addr regs mem')

def process_context(context):
    jumpto(context.addr)

    if context.regs:
        print "0x{:x}:".format(context.addr)
    for i, reg in enumerate(context.regs):
        if (i + 1) % 4 == 0:
            print "  {}".format(reg)
        else:
            print "  {}".format(reg),
    for mem in context.mem:
        print "  {}".format(mem)

def first_trace_addr():
    global ADDRS
    global INDEX

    INDEX = 0
    process_context(ADDRS[INDEX])

def last_trace_addr():
    global ADDRS
    global INDEX

    INDEX = len(ADDRS) - 1
    process_context(ADDRS[INDEX])

def next_trace_addr():
    global ADDRS
    global INDEX

    if INDEX + 1 == len(ADDRS):
        print "Last address"
    else:
        INDEX += 1
        process_context(ADDRS[INDEX])

def prev_trace_addr():
    global ADDRS
    global INDEX

    if INDEX == 0:
        print "First address"
    else:
        INDEX -= 1
        process_context(ADDRS[INDEX])

def goto_trace_addr():
    global ADDRS
    global ADDRS_MAP
    global INDEX

    addr = AskAddr(here(), "Go to address in trace")

    indexes = ADDRS_MAP.get(addr)

    if not indexes:
        print "Failed to find address"

    elif len(indexes) == 1:
        INDEX = indexes[0]
        process_context(ADDRS[INDEX])

    else:
        i = AskLong(0, "Multiple matches found, choose index: 0-{}"
                .format(len(indexes) - 1))

        if not i in range(len(indexes)):
            print "Invalid index"

        else:
            INDEX = indexes[i]
            process_context(ADDRS[INDEX])

def show_command_list():
    print "Commands:"
    print "---------"
    print "H -- show command list"
    print "0 -- first address in trace"
    print "$ -- last address in trace"
    print "j -- next address in trace"
    print "k -- previous address in trace"
    print "G -- go to address in trace"

def main():
    global TRACE_FILE
    global ADDRS
    global ADDRS_MAP
    global Context
    global first_trace_addr
    global last_trace_addr
    global next_trace_addr
    global prev_trace_addr

    TRACE_FILE = AskFile(0, "*.txt", "Select trace file")
    if not TRACE_FILE:
        Warning("Failed to select trace file")
        return

    with open(TRACE_FILE) as lines:
        print "Processing trace..."
        adjust = 0
        for i, line in enumerate(lines):
            line = line.strip()

            # Skip the comments.
            if line.startswith("#"):
                adjust += 1
                continue

            split = line.split(" ; ")
            addr = int(split[0], 16)

            regs = []
            mem  = []
            for x in split[1:]:
                if x.startswith("mem"):
                    mem.append(x)
                else:
                    regs.append(x)

            context = Context(addr, regs, mem)

            ADDRS.append(context)

            if not ADDRS_MAP.get(addr):
                ADDRS_MAP[addr] = []

            ADDRS_MAP[addr].append(i - adjust)  # adjust for the header
            # print "addr: 0x{:x}".format(addr)
        print "Done"

    if len(ADDRS) == 0:
        Warning("No addresses found")
        return

    idaapi.compile_idc_text('static show_command_list() { RunPythonStatement("show_command_list()"); }')
    idaapi.compile_idc_text('static first_trace_addr() { RunPythonStatement("first_trace_addr()"); }')
    idaapi.compile_idc_text('static last_trace_addr() { RunPythonStatement("last_trace_addr()"); }')
    idaapi.compile_idc_text('static next_trace_addr() { RunPythonStatement("next_trace_addr()"); }')
    idaapi.compile_idc_text('static prev_trace_addr() { RunPythonStatement("prev_trace_addr()"); }')
    idaapi.compile_idc_text('static goto_trace_addr() { RunPythonStatement("goto_trace_addr()"); }')

    # To delete: 'del_idc_hotkey(<KEY>)'.
    add_idc_hotkey("Shift-h", "show_command_list")
    add_idc_hotkey("0", "first_trace_addr")
    add_idc_hotkey("$", "last_trace_addr")
    add_idc_hotkey("j", "next_trace_addr")
    add_idc_hotkey("k", "prev_trace_addr")
    add_idc_hotkey("Shift-g", "goto_trace_addr")

    show_command_list()

main()
```

While this significantly helped with reverse engineering, we still had to find
bugs manually, which doesn't scale.  We didn't try fuzzing since it's mostly
pointless without code coverage and we didn't want to implement all that.

### Symbolic Execution

Since we were familiar with [Manticore], we decided to try symbolic execution
instead.  This method was also used by the Quarkslab researchers.

Manticore is a complex project, so it's great that we had our own simple
emulator to compare the results to.  Manticore worked pretty well.  The only
things we had to do were:

- increasing the SMT timeout (see `manticore.core.smtlib.solver`)
- adding some `state.constrain(a == b)` for magic values/sizes
- abandoning uninteresting branches to speed up the analysis
- writing an ELF wrapper script.

Manticore has support for ELF, but our binary is for bare metal.  So we just
wrapped it into ELF, setting the entry point to the dispatcher.

### OOB Read

After a while (maybe 40 minutes on a laptop), Manticore found a crash (OOB
read) in metadata parsing in the PLUTON_DECODE_CAPABILITIES handler.

This happened because the code doesn't check whether
`ImageMetadataHeader.SectionCount` is within file bounds.  So the code keeps
looping until it hits unmapped memory.  The same issue is present in
other firmware components that parse the metadata.

```
0010ACD4 3B 18       ADDS    R3, R7, R0      ; r3 = ptr to the start of 4X4M in the buffer/file
0010ACD6 3C 58       LDR     R4, [R7,R0]     ; r4 = 4X4M metadata magic
0010ACD8 97 48       LDR     R0, ='M4X4'     ; metadata magic check
0010ACDA 84 42       CMP     R4, R0
...
0010ACDE 5D 68       LDR     R5, [R3,#4]     ; r5 = ImageMetadataHeader.SectionCount
0010ACE0 00 2D       CMP     R5, #0
                             ^^ not checked whether the number of sections is within file/buffer bounds
...
0010ACE4 03 F1 08 04 ADD.W   R4, R3, #8      ; goes here if the number of sections > 0
0010ACE4                                     ; r4 = ImageMetadataSectionHeader
0010ACE8 4F F0 00 0C MOV.W   R12, #0         ; r12 = counter
...
loop:
...
0010ACF2 60 88       LDRH    R0, [R4,#2]     ; r0 = ImageMetadataSectionHeader.DataLength
                                  ^^^^^ OOB read from here (null ptr == crash)
...
0010ACF8 0C F1 01 0C ADD.W   R12, R12, #1    ; counter += 1
...
0010ACFE 65 45       CMP     R5, R12         ; cmp counter to section count
...
0010AD02 F3 D1       BNE     loop            ; more sections to parse
```

On the device, this doesn't happen because the memory is mapped.  And it would
never lead to any issues because the code after that does more checks,
which would never pass with a malformed file.  The read value is not
used/leaked to the user either.  And DoS is out of scope too.  So we didn't
even bother reporting this.

After this, the code starts doing even more checks, likely performing signature
verification.  There's still quite a bit of code there, which might contain
bugs, but without knowing the memory state of the device, emulating it
properly wasn't possible.

We considered full system emulation, but the development time required ruled
that out pretty fast.  Then we started looking at hardware debugging,
but we couldn't find a way to enable it in time.

## Source-based Fuzzing

Early on, we tried porting ASXIPFS to userspace in order to fuzz it with
[libFuzzer].  The code is full of casts and dereferences that just look weird.
This didn't work well, however, because it would require porting half of the
kernel to get sensible results.  And in the end, it would still require you
to flash a custom image, which is not the type of bug we were interested in.

Similarly, we briefly played around with [syzkaller] with the intention to fuzz
AZSPIO sockets.  These sockets are used for communication between apps.
There is a firewall based on apps' component IDs.  We ported the code to the
vanilla kernel commenting out the interactions with the Azure Sphere Linux
Security Module (LSM), which included the component ID checks.  We
also had to limit syzkaller to a set of interesting networking syscalls
and provide definitions for our new sockets.

Here's our config file:

```
{
        "target": "linux/amd64",
        "http": "127.0.0.1:56741",
        "workdir": "/home/test/gopath/src/github.com/google/syzkaller/workdir_thirdparty",
        "kernel_obj": "/home/test/linux_modified",
        "image": "/home/test/image/stretch.img",
        "sshkey": "/home/test/image/stretch.id_rsa",
        "syzkaller": "/home/test/gopath/src/github.com/google/syzkaller",
        "procs": 8,
        "type": "qemu",
        "enable_syscalls": [
                "socket$azspio",
                "bind$azspio",
                "connect$azspio",
                "sendmsg",
                "recvmsg",
                "getsockname$azspio",
                "ioctl",
                "poll",
                "close"
        ],
        "vm": {
                "count": 4,
                "kernel": "/home/test/linux_modified/arch/x86/boot/bzImage",
                "cpu": 2,
                "mem": 2048
        }
}
```

And the definitions in `sys/linux/socket_azspio.txt`:

```c
# AF_AZSPIO support.

include <linux/socket.h>
include <linux/net.h>
include <uapi/linux/azspio.h>

resource sock_azspio[sock]

socket$azspio(domain const[AF_AZSPIO], type const[0x80002], proto const[0]) sock_azspio

bind$azspio(fd sock_azspio, addr ptr[in, sockaddr_azspio], addrlen len[addr])

connect$azspio(fd sock_azspio, addr ptr[in, sockaddr_azspio], addrlen len[addr], flags const[0])

getsockname$azspio(fd sock_azspio, addr ptr[in, sockaddr_azspio], addrlen len[addr], peer const[0])

sockaddr_azspio {
        sa_family       const[AF_AZSPIO, int16]
        sa_port         const[0, int16]
        sa_component_id array[const[0x41, int8], 16]
}
```

In the end, our modifications costed us because Talos researchers found a [bug]
there.  The reason we fuzzed on x86_64 is because there's KASAN available in
the vanilla kernel.  And while there's a [patch] for ARM, we didn't know if it
would work.  We didn't put much effort into this one because it initially
looked like two apps would be required to trigger anything here (due to
firewall checks), which would limit the severity.  But we were proven wrong by
Talos researchers, nice work!

By the way, we noticed the special devices in ASXIPFS too (where another Talos
bug was found), but it didn't raise any flags since we didn't look at MTD at
all.

Similarly, the [async stuff] in ioctls was marked as potentially interesting, but
we never got around to testing it.  There's just too many of these issues
during review to act on all of them without a clear goal in mind.

## Third-Party Services
### wpa_supplicant
Another service shipped with Azure Sphere is `wpa_supplicant`, which comes as part of the firmware service/application package `networkd`.  We found multiple `wolfSSL_sk_value` calls (inside `tls_match_alt_subject_component` and `tls_match_suffix`) not being verified, which could lead to a null pointer dereference.  This was reported and the issues were addressed in Azure Sphere 20.07 `0014-Use-Gen-Name-Object.patch` patch file for `src/crypto/tls_wolfssl.c`.  According to Microsoft, this didn’t qualify for any payout as it didn’t meet the requirements for a successful submission.

```c
@@ -588,14 +588,14 @@ static int tls_match_alt_subject_component(WOLFSSL_X509 *cert, int type,
 
 	for (i = 0; ext && i < wolfSSL_sk_num(ext); i++) {
 		gen = wolfSSL_sk_value(ext, i);
-		if (gen->type != type)
+		if (gen == NULL || gen->type != type)
 			continue;
-		if (os_strlen((char *) gen->obj) == len &&
-		    os_memcmp(value, gen->obj, len) == 0)
+		if (wolfSSL_ASN1_STRING_length(gen->d.ia5) == len &&
+		    os_memcmp(value, wolfSSL_ASN1_STRING_data(gen->d.ia5), len) == 0)
 			found++;
 	}
```
and
```c
@@ -693,13 +693,13 @@ static int tls_match_suffix(WOLFSSL_X509 *cert, const char *match, int full)
 
 	for (j = 0; ext && j < wolfSSL_sk_num(ext); j++) {
 		gen = wolfSSL_sk_value(ext, j);
-		if (gen->type != ALT_NAMES_OID)
+		if (gen == NULL || gen->type != ALT_NAMES_OID)
 			continue;
 		dns_name++;
```
## Conclusion

The attack surface is pretty limited here.  In order to reach more code, you
need to escalate privileges first, which essentially requires finding an 0-day
in a stripped down Linux kernel.  Once this became clear, and knowing how
many people were involved in this at the same time, we stopped researching.

Finding bugs manually is time-consuming and you always feel like you're missing
out by not looking at other components.  A smarter way to approach this would be
to develop a Linux kernel (or any other common software) fuzzer capable of
finding bugs in the upstream code first, then start applying for bounties.
Of course, this itself is a serious undertaking, but at least it's generic
enough to be interesting to different parties, not just for a single
time-limited bounty.  As of writing this post, almost all of the [reported
issues] mostly focus on the kernel.

[bounty]: https://www.microsoft.com/en-us/msrc/azure-security-lab
[payout]: https://www.microsoft.com/en-us/msrc/bounty-microsoft-azure
[dev board]: https://azure.microsoft.com/en-us/services/azure-sphere/get-started/
[ARM security features]: https://community.arm.com/developer/ip-products/processors/f/classic-processors-forum/2011/how-to-force-arm-core-into-debug-state-when-dbgen-was-tied-low/6759#6759
[enabled debugging]: https://docs.microsoft.com/en-us/azure-sphere/app-development/develop-debug-rt-app
[Avnet AES-MS-MT3620-M-G Module Data Sheet and User Manual]: https://www.avnet.com/opasdata/d120001/medias/docus/197/Datasheet%20and%20User%20Manual%20AES-MS-MT3620-M-G%20Module%20(v1_3).pdf
[TUN/TAP]: https://en.wikipedia.org/wiki/TUN/TAP
[SLIP]: https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol
[MT3620 Datasheet]: https://d86o2zu8ugzlg.cloudfront.net/mediatek-craft/documents/mt3620/MT3620-Datasheet-v1.5.pdf
[JTAGulator]: http://www.grandideastudio.com/jtagulator/
[low temperature solder]: https://www.youtube.com/watch?v=UmD7F0--7Lc
[hot air gun]: https://www.youtube.com/watch?v=vva2t21sOAs
[Blu Tack]: https://en.wikipedia.org/wiki/Blu_Tack
[pull all these three up]: https://learn.adafruit.com/circuit-playground-digital-input/pull-it-up-or-down
[datasheet with schematics]: http://cloudconnectkits.org/sites/default/files/AES-MS-MT3620-SK-G_SCH_2019-03-06.PDF
[chip decapping]: https://labs.f-secure.com/archive/dont-try-this-at-home-decapping-ics/
[Arty A7-35T]: https://store.digilentinc.com/arty-a7-artix-7-fpga-development-board-for-makers-and-hobbyists/
[ChipWhisperer]: http://wiki.newae.com/Main_Page
[PS3]: https://www.reddit.com/r/ReverseEngineering/comments/aujxs/geohot_reveals_his_ps3_exploit/
[Microchip SAM L11]: https://www.youtube.com/watch?v=4u6BAH8mEDw
[Nintendo Switch]: https://ftp.fau.de/cdn.media.ccc.de/contributors/koeln/open_chaos/2018/h264-hd/openchaos-1806-eng-Glitching_the_Switch_hd.mp4
[Xbox 360]: https://github.com/gligli/tools/blob/b5c8b9ecdbf5b33476ae97a777fe8ff2e2181482/reset_glitch_hack/reset_glitch_hack.txt
[SDK]: https://docs.microsoft.com/en-us/azure-sphere/install/install-sdk
[dnSpy]: https://github.com/0xd4d/dnSpy
[dotPeek]: https://www.jetbrains.com/decompiler/
[Fiddler]: https://www.telerik.com/fiddler
[XMODEM]: http://web.mit.edu/6.115/www/amulet/xmodem.htm
[COBS]: https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing
[provides]: https://docs.microsoft.com/en-us/azure-sphere/hardware/factory-floor-tasks
[JSON]: https://prod.releases.sphere.azure.net/versions/mt3620an.json
[Cortex-M4 Devices Generic User Guide]: https://static.docs.arm.com/dui0553/a/DUI0553A_cortex_m4_dgug.pdf
[here]: https://3rdpartysource.microsoft.com/
[Beyond Compare]: https://www.scootersoftware.com/
[Diaphora]: https://github.com/joxeankoret/diaphora
[size constraints]: https://www.youtube.com/watch?v=KY1vRrS9Lrk
[`HelloWorld_HighLevelApp`]: https://github.com/Azure/azure-sphere-samples/tree/master/Samples/HelloWorld/HelloWorld_HighLevelApp
[escalate privileges]: https://talosintelligence.com/vulnerability_reports/TALOS-2020-1131
[Samsung]: https://www.youtube.com/watch?v=uXH5LJGRwXI
[TrustZone]: https://github.com/quarkslab/samsung-trustzone-research
[Unicorn]: https://www.unicorn-engine.org/
[Manticore]: https://github.com/trailofbits/manticore/
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[syzkaller]: https://github.com/google/syzkaller
[bug]: https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1118
[patch]: https://lwn.net/Articles/791306/
[async stuff]: https://talosintelligence.com/vulnerability_reports/TALOS-2020-1117
[reported issues]: https://techcommunity.microsoft.com/t5/internet-of-things/azure-sphere-20-07-security-enhancements/ba-p/1548973
[Georgi Angelov]: https://github.com/Wiz-IO/platform-azure/wiki
