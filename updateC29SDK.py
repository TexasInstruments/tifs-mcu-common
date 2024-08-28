import sys
import os
import shutil

sdk_folder = "../c29_sdk"

devices = ["f29h85x"]
components = [
    os.path.join("drivers", "hsmclient"),
    os.path.join("drivers", "secure_ipc_notify"),
]

for device in devices :

    #copy tools/boot folder inside tools/boot
    src_path = os.path.join("tools", "boot")
    dest_path = os.path.join(sdk_folder, "mcu_sdk_" + device, "tools", "boot")
    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)
    shutil.copytree(src_path, dest_path)


    #copy the specified components from drivers folder to sdk/source/security.
    #copy only the required soc folders. And update the include paths
    for component in components :
        src_path = component
        dest_path = os.path.join(sdk_folder, "mcu_sdk_" + device, "source", "security", component)

        if os.path.exists(dest_path):
            shutil.rmtree(dest_path)

        for root, dirs, files in os.walk(src_path):
            for file in files :
                # skip other soc files
                if "soc" in root and device not in root and os.path.basename(root) != "soc":
                    continue

                rel_path = root.replace(src_path, "")

                # create the folder if not already present
                dest_file_path = dest_path + os.sep + rel_path
                if not os.path.exists(dest_file_path):
                    os.makedirs(dest_file_path)

                #copy the file
                src_file_path = os.path.join(root, file)
                dest_file_path = os.path.join(dest_file_path, file)
                shutil.copyfile(src_file_path, dest_file_path)

                # for c and h files, update the include paths
                if(dest_file_path.endswith((".h", ".c"))):
                    # read the file contents
                    with open(dest_file_path, 'r', encoding="utf8") as file:
                        filedata = file.read()

                    #replace the paths
                    filedata = filedata.replace('drivers/hw_include', 'security/drivers/hw_include')
                    filedata = filedata.replace('security_common/drivers', 'security/drivers')
                    filedata = filedata.replace('security/drivers/hw_include/f29h85x/', 'security/drivers/hw_include/')

                    # write back the updated contents
                    with open(dest_file_path, 'w',  encoding="utf8") as file:
                        file.write(filedata)