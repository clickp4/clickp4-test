SWITCH_DIR=/home/netarchlab/bmv2/targets/simple_switch
CONTROLLER_DIR=/home/netarchlab/odb/router
CONTROLLER_IP=101.6.30.157
CONTROLLER_PORT=40123
INTF=-i 1@peth1 -i 2@peth2
LOG=-L off

compile:
	@p4c-bmv2 motivation.p4 --json motivation.json

run: compile

	@cp motivation.json $(SWITCH_DIR)
	@cd $(SWITCH_DIR)&&sudo bash simple_switch motivation.json $(INTF) $(LOG)
 
 run-net: compile
	@cp motivation.json $(SWITCH_DIR)
	@bash net.sh

populate:
	@cp commands $(SWITCH_DIR)
	@cd $(SWITCH_DIR)&&./runtime_CLI <commands

populate-net:
	@cp commands $(SWITCH_DIR)
	@cd $(SWITCH_DIR)&&./runtime_CLI <commands
	@cd $(SWITCH_DIR)&&./runtime_CLI --thrift-port 9091 <commands
	@cd $(SWITCH_DIR)&&./runtime_CLI --thrift-port 9092 <commands

setup:
	@echo TODO