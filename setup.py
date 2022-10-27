import setuptools


setuptools.setup(
    python_requires=">=3.6.0",
    setup_requires=["pbr"],
    install_requires=[
        "six>=1.11.0",
    ],
    classifiers=[
        (
            "License :: OSI Approved :: "
            "GNU Lesser General Public License v3 or later (LGPLv3+)"
        ),
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
    ],
    pbr=True,
)
