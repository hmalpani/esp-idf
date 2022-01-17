idf_build_get_property(project_dir PROJECT_DIR)
idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES test_rsa_private_key.pem ca_cert.pem)
