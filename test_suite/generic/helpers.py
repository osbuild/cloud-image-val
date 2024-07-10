from test_suite import conftest


def instance_data(host):
    values_to_find = [host.backend.hostname]
    values_to_find.extend(host.addr(host.backend.hostname).ipv4_addresses)

    return conftest.__get_instance_data_from_json(
        key_to_find='address', values_to_find=values_to_find
    )
