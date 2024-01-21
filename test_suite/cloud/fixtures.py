import pytest


@pytest.fixture(scope='function')
def initialize_efs_env(request, storage):
    """
    Use terraform script to initialize the env for the EFS Utils verification
    """
    # TODO
    # Need to update the terraform script initialization to add also the NFS device for this test
    function_instance = request.node.cls
    # run terraform script

    def finalizer():
        function_instance.infra_controller.destroy_infra()

    request.addfinalizer(finalizer)
