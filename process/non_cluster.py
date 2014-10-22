from qemu import qemu
from fuzz_configuration.xml_parser import xml_parser
from random import shuffle

def non_cluster_non_multiprocessing(target_object, exec_name, exec_list, exec_path, testcase_path, test_path, reload_test, shuffle_test):
    replay = reload_test
    path_prefix = ""
    data = xml_parser(path_prefix + test_path, path_prefix + testcase_path, path_prefix + exec_path).calc_tests(exec_name)

    #if shuffle_test:
    #    shuffle(data)

    if exec_list != []:
        new_data = []
        for e in exec_list:
            new_data.append(data[e])
        data = new_data

    qemu_object = qemu("configurations/" + target_object, "", "", "/tmp/vusbf_" + str(1) + "_socket", 0, 0)

    qemu_object.start()

    print "Number of tests: " + str(len(data))
    for e in data:
        print "TEST #" + str(e[0])
        qemu_object.fire(e, "ssss")
        if not qemu_object.log_qemu_output_select("./log/vusbf_log_" + str(1), "TEST #" + str(e[0]), "s"):
            qemu_object.fire(e, "ssss")
        if replay:
            qemu_object.reload()
