from setuptools import setup, find_packages, Command
import subprocess, unittest, os, glob, shutil, stat

class InstallCommand(Command):
    description = "installation"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        try:
            if not os.path.exists("zkbp_module/curv"):
                subprocess.run(["git", "clone", "https://github.com/ZenGo-X/curv.git", "zkbp_module/curv"], check=True)
            [shutil.copy(file, "zkbp_module/curv/src/cryptographic_primitives/proofs/") for file in glob.glob("zkbp_module/src/proofs/*")]
            subprocess.run(["maturin", "develop", "-r", "-m", "./zkbp_module/Cargo.toml"], check=True)
            run_test()
        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")
            raise
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

    patterns = ['tests/Bank*', 'Bank*', 'pyledger/examples/Bank*','pyledger/examples/Issuer*']
    for pattern in patterns:
        for file in glob.glob(pattern):
            try:
                os.remove(file)
            except Exception as e:
                print(f"Error deleting {file}: {e}")
    for folder_path in  ["zkbp_module/curv", "zkbp_module/target"]:
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
        'maturin',
        'Flask',
        'numpy',
        'web3==5.18.0',
        'py-solc-x',
    ],
    cmdclass={
        'init': InstallCommand,
        'test': TestCommand,
        'clean': CleanCommand
    },
    author='GT Applied Research JP-MorganChase',
    description='Installation of Python package of Padl',
    url='https://github.com/yourusername/your-repo',
)
