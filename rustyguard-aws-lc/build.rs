// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

fn main() {
    let mut selected = String::default();
    let mut candidates = vec![];

    // search through the DEP vars and find the selected sys crate version
    for (name, value) in std::env::vars() {
        // if we've selected a prefix then we can go straight to exporting it
        if !selected.is_empty() {
            try_export_var(&selected, &name, &value);
            continue;
        }

        // we're still looking for a selected prefix
        if let Some(version) = name.strip_prefix("DEP_AWS_LC_") {
            if let Some(version) = version.strip_suffix("_INCLUDE") {
                // we've found the selected version so update it and export it
                selected = format!("DEP_AWS_LC_{version}_");
                try_export_var(&selected, &name, &value);
            } else {
                // it started with the expected prefix, but we don't know what the version is yet
                // so save it for later
                candidates.push((name, value));
            }
        }
    }

    assert!(!selected.is_empty(), "missing DEP_AWS_LC_ include");

    // process all of the remaining candidates
    for (name, value) in candidates {
        try_export_var(&selected, &name, &value);
    }
}

fn try_export_var(selected: &str, name: &str, value: &str) {
    assert!(!selected.is_empty(), "missing selected prefix");

    if let Some(var) = name.strip_prefix(selected) {
        eprintln!("cargo:rerun-if-env-changed={name}");
        let var = var.to_lowercase();
        println!("cargo:{var}={value}");
    }
}
