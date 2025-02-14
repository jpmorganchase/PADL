from numpy.ma.core import innerproduct
from setuptools import setup, find_packages, Command
import subprocess, unittest, glob, shutil, stat,platform
import os,sys


def update_cargo_toml(file_path):
    import toml
    # Load existing Cargo.toml content or create a new structure
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            cargo_data = toml.load(file)
    else:
        cargo_data = {}
    dependencies = {
        "ark-bn254": "0.4",
        "ark-ec": "0.4",
        "ark-std": "0.4",
        "ark-ff": "0.4",
        "ark-serialize": "0.4",
    }
    # Ensure the `[dependencies]` section exists
    if 'dependencies' not in cargo_data:
        cargo_data['dependencies'] = {}

    # Add or update dependencies
    cargo_data['dependencies'].update(dependencies)

    # Write back to the Cargo.toml file
    with open(file_path, 'w') as file:
        toml.dump(cargo_data, file)
    print(f"Updated {file_path} successfully.")


def replace_in_file(file_path):
    try:
        # Open the Rust file to read its content
        with open(file_path, 'r') as file:
            file_content = file.read()

        # Perform the replacements
        updated_content = file_content.replace('Secp256k1', 'Bn254').replace('secp256_k1', 'bn254')

        # Write the updated content back to the file
        with open(file_path, 'w') as file:
            file.write(updated_content)

        print(f"Replacements done in {file_path}")

    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

class InstallCommand(Command):
    description = "installation"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        subprocess.check_call([sys.executable, "-m", "pip", "install", 'toml', 'maturin', 'Flask', 'numpy'])
        try:
            # clone kzen curv and bulletproofs and extend them to bn254, and additional proofs.
            if not os.path.exists("zkbp_module/curv"):
                subprocess.run(["git", "clone", "https://github.com/ZenGo-X/curv.git", "zkbp_module/curv"], check=True)
            if not os.path.exists("zkbp_module/bulletproofs"):
                subprocess.run(["git", "clone", "https://github.com/ZenGo-X/bulletproofs.git", "zkbp_module/bulletproofs"], check=True)

            # add additional sigma protocols
            [shutil.copy(file, "zkbp_module/curv/src/cryptographic_primitives/proofs/") for file in glob.glob("zkbp_module/src/proofs_ext/*")]
            # add 254bn wrapper for curv lib
            [shutil.copy(file, "zkbp_module/curv/src/elliptic/curves/") for file in
            glob.glob("zkbp_module/src/curv_ext/*")]
            update_cargo_toml("zkbp_module/curv/cargo.toml")

            replace_in_file("zkbp_module/bulletproofs/src/proofs/inner_product.rs")
            replace_in_file("zkbp_module/bulletproofs/src/proofs/range_proof.rs")
            replace_in_file("zkbp_module/bulletproofs/src/proofs/range_proof_wip.rs")
            replace_in_file("zkbp_module/bulletproofs/src/proofs/weighted_inner_product.rs")

            # Run the sed command to replace '&8' with '8' in the specified file
            file_path="./zkbp_module/curv/src/arithmetic/big_native/primes.rs"
            # Adjust sed command for macOS if needed
            is_macos = platform.system() == 'Darwin'
            # fixing issue on original curv implementation
            if is_macos:
                sed_command = ['sed', '-i', '', 's/&8/8/g', file_path]  # macOS version
            else:
                sed_command = ['sed', '-i', 's/&8/8/g', file_path]  # Linux/other version
            result = subprocess.run(sed_command, check=True, capture_output=True, text=True)
            subprocess.run(["maturin", "develop", "-r", "-m", "./zkbp_module/Cargo.toml"], check=True)
            run_test()
        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")
            raise

class ContractCommand(Command):
    description = "contract download"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        openzeppelin_download()    

def openzeppelin_download():
    # Clone the repository with filtering and no checkout
    subprocess.run([
        "git", "clone", "--filter=blob:none", "--no-checkout",
        "https://github.com/OpenZeppelin/openzeppelin-contracts.git",
        "@openzeppelin"
    ], check=True)

    # Change directory to the cloned repository
    os.chdir("@openzeppelin")

    # Set sparse-checkout to cone mode
    subprocess.run(["git", "sparse-checkout", "set", "--cone"], check=True)

    # Checkout the master branch
    subprocess.run(["git", "checkout", "master"], check=True)

    # Set sparse-checkout to include only the contracts directory
    subprocess.run(["git", "sparse-checkout", "set", "contracts"], check=True)

    # Change back to the original directory
    os.chdir("..")


class TestCommand(Command):
    description = "Run unittests."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        run_test()

def run_test():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests')
    test_runner = unittest.TextTestRunner(verbosity=2)
    test_runner.run(test_suite)
    clean()

def clean():
    # Define patterns for files to remove
    def remove_readonly(func, path, _):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    patterns = ['tests/Bank*','tests/Issuer*', 'Bank*', 'pyledger/examples/Bank*','pyledger/examples/Issuer*','pyledger/compiled_*']
    for pattern in patterns:
        for file in glob.glob(pattern):
            try:
                os.remove(file)
            except Exception as e:
                print(f"Error deleting {file}: {e}")
    for folder_path in  ["zkbp_module/curv", "zkbp_module/bulletproofs", "zkbp_module/target"]:
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            try:
                shutil.rmtree(folder_path, onerror=remove_readonly)
                print(f"Deleted: {folder_path}")
            except Exception as e:
                print(f"Error deleting {folder_path}: {e}")

class CleanCommand(Command):
    description = "Clean up files starting with 'Bank'."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        clean()

setup(
    name='pyledger',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'toml',
        'maturin',
        'Flask',
        'numpy',
        'web3==5.18.0',
        'py-solc-x',
    ],
    cmdclass={
        'init': InstallCommand,
        'test': TestCommand,
        'clean': CleanCommand,
        'contract': ContractCommand
    },
    author='GT Applied Research JP-MorganChase',
    description='Installation of Python package of Padl',
    url='https://github.com/yourusername/your-repo',
)

