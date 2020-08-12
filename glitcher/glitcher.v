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
