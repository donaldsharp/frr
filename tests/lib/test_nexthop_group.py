import frrtest

class TestNexthopGroup(frrtest.TestMultiOut):
    program = './test_nexthop_group'

TestNexthopGroup.onesimple('Order Correct')
