# Copyright 2023-present Intel
#
# SPDX-License-Identifier: Apache-2.0

import yaml
import json

sd_core_file = 'sd-core-5g-values.yaml'
with open(sd_core_file, 'r') as yaml_file:
    values_5g = yaml.safe_load(yaml_file)

roc_file = 'roc-5g-models.json'
with open(roc_file, 'r') as json_file:
    values_roc = json.load(json_file)

# Subscribers and Imsis
subscribers = values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['subscribers']
values_roc['Updates']['site-2.1.0'][0]['sim-card'].clear()
values_roc['Updates']['site-2.1.0'][0]['device'].clear()
imsi_ueId_relation = {}
index = 1

for subs in subscribers:
    try:
        imsi_start = int(subs['ueId-start'])
        # This is needed when the MNC/IMSI starts with "0s"
        len_start = len(subs['ueId-start'])
        len_start_int = len(str(imsi_start))
        append_zeros = "0" * (len_start - len_start_int)
    except:
        print("Invalid IMSI")
    try:
        imsi_end = int(subs['ueId-end'])
    except:
        print("Invalid IMSI")

    for imsi in range(imsi_start, imsi_end + 1):
        input = {'sim-id': 'aiab-sim-' + str(index),
                 'display-name': 'UE ' + str(index) + ' Sim', 'imsi': append_zeros + str(imsi)}
        values_roc['Updates']['site-2.1.0'][0]['sim-card'].append(input)
        input = {'device-id': 'aiab-ue-' + str(index), 'display-name': 'UE ' + str(
            index), 'sim-card': 'aiab-sim-' + str(index)}
        values_roc['Updates']['site-2.1.0'][0]['device'].append(input)
        imsi_ueId_relation[append_zeros + str(imsi)] = input['device-id']
        index = index + 1

# Device Groups and IP domains
device_groups = values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['device-groups']
values_roc['Updates']['site-2.1.0'][0]['device-group'].clear()
values_roc['Updates']['site-2.1.0'][0]['ip-domain'].clear()
values_roc['Updates']['traffic-class-2.1.0'].clear()

index = 1

for device_group in device_groups:
    device_list = []
    for imsi in device_group['imsis']:
        try:
            device_list.append(
                {'device-id': imsi_ueId_relation[imsi], 'enable': True})
        except:
            print('IMSI {0} does not exist in Devices/Sim cards'.format(imsi))

    input = {'display-name': 'AiaB Users ' + str(index), 'device-group-id': device_group['name'], 'device': device_list, 'ip-domain': device_group['ip-domain-name'], 'mbr': {
        'uplink': device_group['ip-domain-expanded']['ue-dnn-qos']['dnn-mbr-uplink'], 'downlink': device_group['ip-domain-expanded']['ue-dnn-qos']['dnn-mbr-downlink']}, 'traffic-class': 'aiab-class-' + str(index)}
    values_roc['Updates']['site-2.1.0'][0]['device-group'].append(input)

    input = {'admin-status': 'ENABLE', 'display-name': 'IP pool ' + str(index), 'dnn': device_group['ip-domain-expanded']['dnn'], 'dns-primary': device_group['ip-domain-expanded']
             ['dns-primary'], 'ip-domain-id': device_group['ip-domain-name'], 'mtu': device_group['ip-domain-expanded']['mtu'], 'subnet': device_group['ip-domain-expanded']['ue-ip-pool']}
    values_roc['Updates']['site-2.1.0'][0]['ip-domain'].append(input)

    input = {'description': values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['device-groups'][0]['ip-domain-expanded']['ue-dnn-qos']['traffic-class']['name'], 'display-name': 'Class ' + str(index), 'traffic-class-id': 'aiab-class-' + str(index), 'pdb': values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['device-groups'][0]['ip-domain-expanded']['ue-dnn-qos']['traffic-class']['pdb'], 'arp': values_5g['omec-sub-provision'][
        'config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['device-groups'][0]['ip-domain-expanded']['ue-dnn-qos']['traffic-class']['arp'], 'pelr': values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['device-groups'][0]['ip-domain-expanded']['ue-dnn-qos']['traffic-class']['pelr'], 'qci': values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['device-groups'][0]['ip-domain-expanded']['ue-dnn-qos']['traffic-class']['qci']}
    values_roc['Updates']['traffic-class-2.1.0'].append(input)
    index = index + 1

# UPFs and Slices
slices = values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['network-slices']

index = 1

for slice in slices:
    values_roc['Updates']['site-2.1.0'][0]['slice'][index - 1]['default-behavior'] = values_5g['omec-sub-provision']['config'][
        'simapp']['cfgFiles']['simapp.yaml']['configuration']['network-slices'][index - 1]['application-filtering-rules'][0]['rule-name']
    values_roc['Updates']['site-2.1.0'][0]['slice'][index -
                                                    1]['display-name'] = 'AiaB Slice ' + str(index)
    dev_groups = values_5g['omec-sub-provision']['config']['simapp']['cfgFiles'][
        'simapp.yaml']['configuration']['network-slices'][index - 1]['site-device-group']
    values_roc['Updates']['site-2.1.0'][0]['slice'][index -
                                                    1]['device-group'].clear()
    for dev_group in dev_groups:
        input = {'device-group': dev_group, 'enable': True}
        values_roc['Updates']['site-2.1.0'][0]['slice'][index -
                                                        1]['device-group'].append(input)
    values_roc['Updates']['site-2.1.0'][0]['slice'][index -
                                                    1]['slice-id'] = 'aiab-vcs-' + str(index)
    values_roc['Updates']['site-2.1.0'][0]['slice'][index -
                                                    1]['sd'] = values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['network-slices'][index - 1]['slice-id']['sd']
    values_roc['Updates']['site-2.1.0'][0]['slice'][index - 1]['sst'] = str(
        values_5g['omec-sub-provision']['config']['simapp']['cfgFiles']['simapp.yaml']['configuration']['network-slices'][index - 1]['slice-id']['sst'])
    index = index + 1

with open(roc_file, 'w') as outfile:
    outfile.write(json.dumps(values_roc, indent=4))
    outfile.write('\n')
