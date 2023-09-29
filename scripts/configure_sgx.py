#!/usr/bin/env python3

# Copyright 2023-present Intel
#
# SPDX-License-Identifier: Apache-2.0
import os
import subprocess
import logging
import sys
from shutil import which

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


config_values = {
    "PLUGIN_VERSION": os.getenv("PLUGIN_VERSION", default="v0.27.1"),
    "CERT_VERSION": os.getenv("CERT_VERSION", default="v1.11.0"),
}

logging.debug(("\n".join(f'{k}: {v}' for k, v in config_values.items())))


def present(name):
    """Checks if the binary is in the PATH"""
    return which(name) is not None


def generate_plugin_url(plugin_type):
    """Generates SGX plugin url"""
    plugin_version = config_values.get("PLUGIN_VERSION")

    if plugin_type == "nfd":
        return 'https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/nfd/?ref={0}'.format(plugin_version)
    elif plugin_type == "nfd_rules":
        return 'https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/nfd/overlays/node-feature-rules?ref={0}'.format(plugin_version)
    elif plugin_type == "device_plugin_operator":
        return 'https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/operator/default?ref={0}'.format(plugin_version)
    elif plugin_type == "device_plugin":
        return 'https://raw.githubusercontent.com/intel/intel-device-plugins-for-kubernetes/{0}/deployments/operator/samples/deviceplugin_v1_sgxdeviceplugin.yaml'.format(plugin_version)


def enable_sgx_plugin():
    """Installing SGX Plugin in Kubernetes"""
    plugin_version = config_values.get("PLUGIN_VERSION")
    nfd = "kubectl apply -k {0}".format(generate_plugin_url("nfd"))
    msg = "Installing NFD SGX Plugin in version {0}".format(plugin_version)
    logging.debug(msg)
    run_command(nfd)
    nfd_rules = "kubectl apply -k {0}".format(generate_plugin_url("nfd_rules"))
    msg = "Installing NFD SGX Rules in version {0}".format(plugin_version)
    logging.debug(msg)
    run_command(nfd_rules)
    device_plugin_operator = "kubectl apply -k {0}".format(
        generate_plugin_url("device_plugin_operator"))
    msg = "Installing SGX Device Plugin Operator in version {0}".format(plugin_version)
    logging.debug(msg)
    run_command(device_plugin_operator)
    device_plugin = "kubectl apply -k {0}".format(
        generate_plugin_url("device_plugin"))
    msg = "Installing SGX Device Plugin in version {0}".format(
        plugin_version)
    logging.debug(msg)
    run_command(device_plugin)


def is_nfd_installed():
    """Checks if Node is installed on the system"""
    run_command(
        "kubectl get no -o json | jq .items[].metadata.labels | grep intel.feature.node.kubernetes.io/sgx")


def is_sgx_enabled():
    """Checks if SGX is installed on the system"""
    try:
        with open("/proc/cpuinfo", "r") as cpuinfo:
            return "sgx" in cpuinfo.read()
    except FileNotFoundError:
        logging.debug(
            "Cannot find /proc/cpuinfo. This script is intended to be run on Linux.")
        return False


def install_cert_manager():
    """Installs cert manager, dependency for the SGX plugin"""
    cert_maneger_repo = "helm repo add jetstack https://charts.jetstack.io"
    logging.debug("Adding jetstack charts")
    run_command(cert_maneger_repo)
    cert_manager = "helm install --wait cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --version {0} --set installCRDs=true".format(
        config_values.get("CERT_VERSION"))
    logging.debug("Installing Cert Manager")
    run_command(cert_manager)


def run_command(command):
    """Runs system command"""
    try:
        subprocess.run(command, shell=True, check=True,
                       stdout=subprocess.DEVNULL)
        logging.debug("Command {0} executed successfully.".format(command))
    except subprocess.CalledProcessError:
        logging.debug("Failed to run command {0}.".format(command))


def run_apt_command(command):
    """Runs apt command"""
    run_command('sudo apt-get update')
    logging.debug("Updating APT Cache")

    run_command(command)
    logging.debug("Running APT Command {0}.".format(command))


def main():
    if not is_sgx_enabled():
        logging.error("Intel SGX is not enabled on this system.")
        return
    if not present("kubectl"):
        logging.error("Kubectl is not present on this system.")
        return
    if not present("helm"):
        logging.error("Helm binary is not present on this system.")
        return
    try:
        install_cert_manager()
    except Exception as e:
        logging.error("Failed to install Cert manager")
    try:
        enable_sgx_plugin()
    except Exception as e:
        logging.error("Failed to install SGX plugin")


if __name__ == "__main__":
    main()
