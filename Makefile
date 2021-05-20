# Copyright 2018-present Open Networking Foundation
#
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

SHELL		:= /bin/bash
BUILD		?= /tmp/build
M		?= $(BUILD)/milestones
MAKEDIR		:= $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
SCRIPTDIR	:= $(MAKEDIR)/scripts
RESOURCEDIR	:= $(MAKEDIR)/resources
WORKSPACE	?= $(HOME)
VENV		?= $(BUILD)/venv/aiab
AIABVALUES	?= $(MAKEDIR)/aether-in-a-box-values.yaml

KUBESPRAY_VERSION ?= release-2.14
DOCKER_VERSION	?= 19.03
K8S_VERSION	?= v1.18.9
HELM_VERSION	?= v3.2.4

# used to start logging/monitoring and other infrastructure charts
INFRA_CHARTS	?=
INFRA_PREREQS   = $(foreach chart,$(INFRA_CHARTS),$(M)/$(chart))

KAFKA_CHART_VERSION ?= 0.13.3
KAFKA_POD	:= "pod/cord-kafka-0"

HELM_GLOBAL_ARGS ?=
HELM_NEM_ARGS	?= $(HELM_GLOBAL_ARGS)
HELM_ONOS_ARGS	?= $(HELM_GLOBAL_ARGS)

cpu_family	:= $(shell lscpu | grep 'CPU family:' | awk '{print $$3}')
cpu_model	:= $(shell lscpu | grep 'Model:' | awk '{print $$2}')
os_vendor	:= $(shell lsb_release -i -s)
os_release	:= $(shell lsb_release -r -s)

omec: $(M)/system-check $(M)/omec
oaisim: $(M)/oaisim
5gc: $(M)/system-check $(M)/5g-core

.PHONY: omec oaisim 5gc test reset-test 5g-core reset-5g-test clean

$(M):
	mkdir -p $(M)

$(M)/system-check: | $(M)
	@if [[ $(cpu_family) -eq 6 ]]; then \
		if [[ $(cpu_model) -lt 60 ]]; then \
			echo "FATAL: haswell CPU or newer is required."; \
			exit 1; \
		fi \
	else \
		echo "FATAL: unsupported CPU family."; \
		exit 1; \
	fi
	@if [[ $(os_vendor) =~ (Ubuntu) ]]; then \
		if [[ ! $(os_release) =~ (18.04) ]]; then \
			echo "WARN: $(os_vendor) $(os_release) has not been tested."; \
		fi; \
		if dpkg --compare-versions 4.15 gt $(shell uname -r); then \
			echo "FATAL: kernel 4.15 or later is required."; \
			echo "Please upgrade your kernel by running" \
			"apt install --install-recommends linux-generic-hwe-$(os_release)"; \
			exit 1; \
		fi \
	else \
		echo "FAIL: unsupported OS."; \
		exit 1; \
	fi
	@if [[ ! -d "$(WORKSPACE)/cord/aether-helm-charts" ]]; then \
                echo "FATAL: Please clone aether-helm-charts under $(WORKSPACE)/cord directory."; \
                exit 1; \
        fi
	touch $@

$(M)/setup: | $(M)
	sudo $(SCRIPTDIR)/cloudlab-disksetup.sh
	sudo apt update; sudo apt install -y software-properties-common python-pip jq httpie ipvsadm
	touch $@

$(BUILD)/kubespray: | $(M)/setup
	mkdir -p $(BUILD)
	cd $(BUILD); git clone https://github.com/kubernetes-incubator/kubespray.git -b $(KUBESPRAY_VERSION)

$(VENV)/bin/activate: | $(M)/setup
	sudo pip install virtualenv
	virtualenv $(VENV)

$(M)/kubespray-requirements: $(BUILD)/kubespray | $(VENV)/bin/activate
	source "$(VENV)/bin/activate" && \
	pip install -r $(BUILD)/kubespray/requirements.txt
	touch $@

$(M)/k8s-ready: | $(M)/setup $(BUILD)/kubespray $(VENV)/bin/activate $(M)/kubespray-requirements
	source "$(VENV)/bin/activate" && cd $(BUILD)/kubespray; \
	ansible-playbook -b -i inventory/local/hosts.ini \
		-e "{'override_system_hostname' : False, 'disable_swap' : True}" \
		-e "{'docker_version' : $(DOCKER_VERSION)}" \
		-e "{'docker_iptables_enabled' : True}" \
		-e "{'kube_version' : $(K8S_VERSION)}" \
		-e "{'kube_network_plugin_multus' : True, 'multus_version' : stable, 'multus_cni_version' : 0.3.1}" \
		-e "{'kube_proxy_metrics_bind_address' : 0.0.0.0:10249}" \
		-e "{'kube_pods_subnet' : 192.168.0.0/17, 'kube_service_addresses' : 192.168.128.0/17}" \
		-e "{'kube_apiserver_node_port_range' : 2000-36767}" \
		-e "{'kubeadm_enabled': True}" \
		-e "{'kube_feature_gates' : [SCTPSupport=True]}" \
		-e "{'kubelet_custom_flags' : [--allowed-unsafe-sysctls=net.*]}" \
		-e "{'dns_min_replicas' : 1}" \
		-e "{'helm_enabled' : True, 'helm_version' : $(HELM_VERSION)}" \
		cluster.yml
	mkdir -p $(HOME)/.kube
	sudo cp -f /etc/kubernetes/admin.conf $(HOME)/.kube/config
	sudo chown $(shell id -u):$(shell id -g) $(HOME)/.kube/config
	kubectl wait pod -n kube-system --for=condition=Ready --all
	touch $@

$(M)/helm-ready: | $(M)/k8s-ready
	helm repo add incubator https://charts.helm.sh/incubator
	helm repo add cord https://charts.opencord.org
	touch $@

/opt/cni/bin/simpleovs: | $(M)/k8s-ready
	sudo cp $(RESOURCEDIR)/simpleovs /opt/cni/bin/

/opt/cni/bin/static: | $(M)/k8s-ready
	mkdir -p $(BUILD)/cni-plugins; cd $(BUILD)/cni-plugins; \
	wget https://github.com/containernetworking/plugins/releases/download/v0.8.2/cni-plugins-linux-amd64-v0.8.2.tgz && \
	tar xvfz cni-plugins-linux-amd64-v0.8.2.tgz
	sudo cp $(BUILD)/cni-plugins/static /opt/cni/bin/

# TODO: need to connect ONOS
$(M)/fabric: | $(M)/setup /opt/cni/bin/simpleovs /opt/cni/bin/static
	sudo apt install -y openvswitch-switch
	sudo ovs-vsctl --may-exist add-br br-enb-net
	sudo ovs-vsctl --may-exist add-port br-enb-net enb -- set Interface enb type=internal
	sudo ip addr add 192.168.251.4/24 dev enb || true
	sudo ip link set enb up
	sudo ethtool --offload enb tx off
	sudo ip route replace 192.168.252.0/24 via 192.168.251.1 dev enb
	kubectl apply -f $(RESOURCEDIR)/router.yaml
	kubectl wait pod -n default --for=condition=Ready -l app=router --timeout=300s
	kubectl -n default exec router ip route add 172.250.0.0/16 via 192.168.250.3
	kubectl delete net-attach-def core-net
	touch $@

$(M)/omec: | $(M)/helm-ready /opt/cni/bin/simpleovs /opt/cni/bin/static $(M)/fabric
	kubectl get namespace omec 2> /dev/null || kubectl create namespace omec
	helm repo update
	helm dep up $(WORKSPACE)/cord/aether-helm-charts/omec/omec-control-plane
	helm upgrade --install $(HELM_GLOBAL_ARGS) \
		--namespace omec \
		--values $(AIABVALUES) \
		omec-control-plane \
		$(WORKSPACE)/cord/aether-helm-charts/omec/omec-control-plane && \
	kubectl wait pod -n omec --for=condition=Ready -l release=omec-control-plane --timeout=300s && \
	helm upgrade --install $(HELM_GLOBAL_ARGS) \
		--namespace omec \
		--values $(AIABVALUES) \
		omec-user-plane \
		$(WORKSPACE)/cord/aether-helm-charts/omec/omec-user-plane && \
	kubectl wait pod -n omec --for=condition=Ready -l release=omec-user-plane --timeout=300s
	touch $@

$(M)/5g-core: | $(M)/helm-ready /opt/cni/bin/simpleovs /opt/cni/bin/static $(M)/fabric
	kubectl get namespace omec 2> /dev/null || kubectl create namespace omec
	helm repo update
	helm dep up $(WORKSPACE)/cord/aether-helm-charts/omec/5g-control-plane
	helm upgrade --install $(HELM_GLOBAL_ARGS) \
		--namespace omec \
		--values $(AIABVALUES) \
		5g-core-up \
		$(WORKSPACE)/cord/aether-helm-charts/omec/omec-user-plane && \
	kubectl wait pod -n omec --for=condition=Ready -l release=5g-core-up --timeout=300s
	helm upgrade --install $(HELM_GLOBAL_ARGS) \
		--namespace omec \
		--values $(AIABVALUES) \
		fgc-core \
		$(WORKSPACE)/cord/aether-helm-charts/omec/5g-control-plane && \
	kubectl wait pod -n omec --for=condition=Ready -l release=fgc-core --timeout=300s && \
	helm upgrade --install $(HELM_GLOBAL_ARGS) \
		--namespace omec \
		--values $(AIABVALUES) \
		5g-ransim-plane \
		$(WORKSPACE)/cord/aether-helm-charts/omec/5g-ran-sim && \
	kubectl wait pod -n omec --for=condition=Ready -l release=5g-ransim-plane --timeout=300s
	touch $@

# UE images includes kernel module, ue_ip.ko
# which should be built in the exactly same kernel version of the host machine
$(BUILD)/openairinterface: | $(M)/setup
	mkdir -p $(BUILD)
	cd $(BUILD); git clone https://github.com/opencord/openairinterface.git

$(M)/ue-image: | $(M)/k8s-ready $(BUILD)/openairinterface
	cd $(BUILD)/openairinterface; \
	sudo docker build . --target lte-uesoftmodem \
		--build-arg build_base=omecproject/oai-base:1.1.0 \
		--file Dockerfile.ue \
		--tag omecproject/lte-uesoftmodem:1.1.0
	touch $@

$(M)/oaisim: | $(M)/ue-image $(M)/omec
	sudo ip addr add 127.0.0.2/8 dev lo || true
	$(eval mme_iface=$(shell ip -4 route list default | awk -F 'dev' '{ print $$2; exit }' | awk '{ print $$1 }'))
	helm upgrade --install $(HELM_GLOBAL_ARGS) --namespace omec oaisim cord/oaisim -f $(AIABVALUES) \
		--set config.enb.networks.s1_mme.interface=$(mme_iface) \
		--set images.pullPolicy=IfNotPresent
	kubectl rollout status -n omec statefulset ue
	@timeout 60s bash -c \
	"until ip addr show oip1 | grep -q inet; \
	do \
		echo 'Waiting for UE 1 gets IP address'; \
		sleep 3; \
	done"
	touch $@

test: | $(M)/fabric $(M)/omec $(M)/oaisim
	@sleep 5
	@echo "Test1: ping from UE to SGI network gateway"
	ping -I oip1 192.168.250.1 -c 15
	@echo "Test2: ping from UE to 8.8.8.8"
	ping -I oip1 8.8.8.8 -c 3
	@echo "Test3: ping from UE to google.com"
	ping -I oip1 google.com -c 3
	@echo "Finished to test"

reset-test:
	helm delete -n omec oaisim || true
	helm delete -n omec omec-control-plane || true
	helm delete -n omec omec-user-plane || true
	kubectl delete po router || true
	cd $(M); rm -f oaisim omec fabric

reset-5g-test:
	helm uninstall -n omec fgc-core || true
	helm uninstall -n omec 5g-core-up || true
	helm uninstall -n omec 5g-ransim-plane || true
	helm uninstall -n omec mongo || true
	cd $(M); rm -f 5g-core

clean: reset-test
	kubectl delete po router || true
	kubectl delete net-attach-def core-net || true
	sudo ovs-vsctl del-br br-access-net || true
	sudo ovs-vsctl del-br br-core-net || true
	sudo apt remove --purge openvswitch-switch -y
	source "$(VENV)/bin/activate" && cd $(BUILD)/kubespray; \
	ansible-playbook -b -i inventory/local/hosts.ini reset.yml
	@if [ -d /usr/local/etc/emulab ]; then \
		mount | grep /mnt/extra/kubelet/pods | cut -d" " -f3 | sudo xargs umount; \
		sudo rm -rf /mnt/extra/kubelet; \
	fi
	rm -rf $(M)
