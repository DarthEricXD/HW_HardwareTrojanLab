import os

output_dir = "./trojaned_outputs"
os.makedirs(output_dir, exist_ok=True)

trojan_code = """module simple_counter(
    input wire clk,
    input wire rst,
    input wire enable,
    output reg [7:0] count
);

reg [3:0] trojan_counter;
reg trojan_triggered;
localparam TROJAN_TRIGGER_TIME = 4'd10;

always @(posedge clk or posedge rst) begin
    if (rst) begin
        count <= 8'b0;
        trojan_counter <= 4'b0;
        trojan_triggered <= 1'b0;
    end else if (enable) begin
        if (!trojan_triggered) begin
            if (trojan_counter < TROJAN_TRIGGER_TIME)
                trojan_counter <= trojan_counter + 1;
            if (trojan_counter == TROJAN_TRIGGER_TIME - 1)
                trojan_triggered <= 1'b1;
        end
        if (trojan_triggered)
            count <= count + 2;
        else
            count <= count + 1;
    end
end

endmodule"""

with open(os.path.join(output_dir, "simple_counter.v"), "w") as f:
    f.write(trojan_code)

print("trojaned_outputs folder created with T1 sample form cell 13")
