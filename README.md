# Reverse engineering binary executables using IDA and Pin

## IDA Pro Plugin:
Static Data Dependence: static_data_dependence.py
Output generated in ./outputs/

## Dynamic Control Dependence using Pin:
1. Install Pin
2. Build the project in VS Studio for Windows (you will need to move dynamic_control_flow.cpp to Pin and rename)
3. Run the output on the executable you want to test
4. Run
```
python dynamic_control_depence.py
```
5. Output generated in ./outputs/