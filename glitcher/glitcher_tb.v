`timescale 1ns / 1ps

module glitcher_tb();

reg i_clk, i_clk_reset, i_glitch, i_pulse;
wire o_clk, o_clk_locked, o_clk_led, o_glitch, o_glitch_led;
// wire [15:0] o_counter;

glitcher glitcher0(
    .i_clk(i_clk),                // e3: 100 MHz crystal oscillator
    .i_clk_reset(i_clk_reset),    // c2: clock reset button
    
    .i_glitch(i_glitch),          // sw0 (a8): glitch vcc input
    
    .i_pulse(i_pulse),            // btn0 (d9): drop voltage (glitch)
    
    .o_clk(o_clk),                // pmod ja, pin2 (b11): 200 MHz clock
    .o_clk_locked(o_clk_locked),  // pmod ja, pin3 (a11): clock ready
    .o_clk_led(o_clk_led),        // ld5 (j5): clock status led
    
    .o_glitch(o_glitch),          // pmod ja, pin 1 (g13): glitch output
    .o_glitch_led(o_glitch_led)   // ld4 (h5): glitch status led
    
    // .o_counter(o_counter)         // glitch counter (for testing)
);

initial
begin
    i_clk = 0;
    i_clk_reset = 1;  // note: the button on the board is inverted
    i_glitch = 1;
    i_pulse = 0;
    
    // Button press.
    #1000 i_clk_reset = 0;
    #10 i_clk_reset = 1;
    
    // Wait until 'o_clk_locked'.
    #2000 i_pulse = 1;
    // Test that 'i_pulse' is dependent on 'o_clk'.
    // Simulate a long button press, greater than the 'counter' period.
    // A real button press would be >104 ms.
    #104_000_000 i_pulse = 0;    
end

always #5 i_clk = ~i_clk;  // clock cycle: 10 ns for 100 MHz

endmodule
