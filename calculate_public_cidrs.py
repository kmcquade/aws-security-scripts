#!/usr/bin/env python
"""
Generate a list of non-company CIDR ranges for usage in Open Policy Agent rules.
"""

from netaddr import IPNetwork, IPAddress, IPRange
import json
import yaml
import click
from os import getcwd
from schema import Schema, SchemaError


COMPANY_CIDRS_SCHEMA = Schema({
    'company_cidrs': [str]
})


@click.command(
    short_help='Generate a list of non-company CIDR ranges for usage in Open Policy Agent rules.'
)
@click.option(
    '--input-file',
    type=click.Path(exists=True),
    default=getcwd() + '/policy/exceptions/company_cidrs.yml',
    help='The path to the company_cidrs.yml file, which should contain a list of company-only CIDR ranges. The '
         'example just has RFC1918 CIDRs. '
)
@click.option(
    '--output-file',
    type=click.Path(exists=True),
    default=getcwd() + '/policy/exceptions/',
    help='The directory to store the non_company_cidrs.yml file'
)
def calculate_public_cidrs(input_file, output_file):
    # netmask_command_calc()
    cfg = read_yaml_file(input_file)
    check_company_cidrs_schema(cfg)
    company_cidr_list = sort_cidrs(cfg['company_cidrs'])
    illegal_cidrs = get_illegal_ranges(company_cidr_list)
    file_contents = {'non_company_cidrs': illegal_cidrs}
    with open(output_file + 'non_company_cidrs.yml', 'w') as results_file:
        yaml.dump(file_contents, results_file)
    print(f"Printed non-company CIDRs to file: {output_file}\n")
    print("Illegal CIDRs:")
    print(json.dumps(illegal_cidrs, indent=2))


def get_new_ip_network(cidr):
    ip_network = IPNetwork(cidr)
    return ip_network


def get_first_address_in_network(cidr):
    ip_network = IPNetwork(cidr)
    return IPAddress(ip_network.first)


def get_last_address_in_network(cidr):
    ip_network = IPNetwork(cidr)
    return IPAddress(ip_network.last)


def get_first_address_in_network_minus_one(cidr):
    ip_network = IPNetwork(cidr)
    return IPAddress(ip_network.first).__sub__(1)


def get_last_address_in_network_plus_one(cidr):
    ip_network = IPNetwork(cidr)
    return IPAddress(ip_network.last).__add__(1)


def netmask_command_calc(cidr_list):
    print(f"netmask -c 0.0.0.0:{get_first_address_in_network_minus_one(cidr_list[0])}")
    i = 0
    how_long = len(cidr_list) + 1
    while i < how_long:
        # print(i)
        if i is len(cidr_list) -1:
            print(f"netmask -c {get_last_address_in_network_plus_one(cidr_list[i])}:255.255.255.255")
            i += 2
        else:
            print(f"netmask -c {get_last_address_in_network_plus_one(cidr_list[i])}:"
                  f"{get_first_address_in_network_minus_one(cidr_list[i + 1])}")
            i += 1


def get_illegal_ranges(cidr_list):
    all_cidrs = []
    first_network_range = IPRange("0.0.0.0", get_first_address_in_network_minus_one(cidr_list[0]))
    for network in first_network_range.cidrs():
        all_cidrs.append(network.cidr.__str__())
    # print(f"netmask -c 0.0.0.0:{get_first_address_in_network_minus_one(CIDR_LIST[0])}")
    i = 0
    how_long = len(cidr_list) + 1
    while i < how_long:
        # print(i)
        if i is len(cidr_list)-1:
            last_network_range = IPRange(get_last_address_in_network_plus_one(cidr_list[i]), '255.255.255.255')
            for network in last_network_range.cidrs():
                all_cidrs.append(network.cidr.__str__())
            i += 2
        else:
            second_network_range = IPRange(get_last_address_in_network_plus_one(cidr_list[i]),
                                           get_first_address_in_network_minus_one(cidr_list[i + 1]))
            for network in second_network_range.cidrs():
                all_cidrs.append(network.cidr.__str__())
            i += 1
    return all_cidrs


def sort_cidrs(cidr_list):
    """Sorts the CIDRs from earliest to latest. For example. 172.16.0.0/12 should be before 192.168.0.0/16."""
    new_cidr_list = []
    temp_cidr_list = []
    for cidr in cidr_list:
        temp_cidr_list.append(IPNetwork(cidr))
    temp_cidr_list.sort()

    for network in temp_cidr_list:
        # print(network.cidr.__str__())
        new_cidr_list.append(network.cidr.__str__())
    return new_cidr_list


def check_schema(conf_schema, conf):
    """
    Validates a user-supplied JSON vs a defined schema.
    :param conf_schema: The Schema object that defines the required structure.
    :param conf: The user-supplied schema to validate against the required structure.
    """
    try:
        conf_schema.validate(conf)
        return True
    except SchemaError as s_e:
        print(s_e)
        return False


def check_company_cidrs_schema(cfg):
    """Determines whether or not the user-provided YAML schema meets expectations"""
    result = check_schema(COMPANY_CIDRS_SCHEMA, cfg)
    if result is True:
        return result
    else:
        raise Exception(f"The provided template does not meet the required schema for the company_cidrs yml file. "
                        f"Please read the instructions")


def read_yaml_file(filename):
    """
    Reads a YAML file, safe loads, and returns the dictionary

    :param filename: name of the yaml file
    :return: dictionary of YAML file contents
    :
    """
    with open(filename, 'r') as yaml_file:
        try:
            cfg = yaml.safe_load(yaml_file)
        except yaml.YAMLError as exc:
            print(exc)
    return cfg


if __name__ == '__main__':
    calculate_public_cidrs()

