// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{AttributeArgs, ItemFn, ReturnType};

#[proc_macro_attribute]
pub fn hsm_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::ItemFn);
    let args = syn::parse_macro_input!(args as syn::AttributeArgs);
    test_impl(input, args).unwrap_or_else(|e| e.to_compile_error().into())
}

fn test_impl(mut input: ItemFn, _args: AttributeArgs) -> Result<TokenStream, syn::Error> {
    // Ensure we tag the function as a test
    let header = quote! {
        #[::core::prelude::v1::test]
    };

    // We'll grab the parameters so we can keep the names in the
    // inner function, then we'll replace the outer function
    // parameters and remove them.
    let parameters = input.sig.inputs.clone();
    input.sig.inputs = Default::default();

    // Support the return of Result<()> for tests
    let (tester, test_impl_sig) = match input.sig.output {
        ReturnType::Default => (
            quote! {
                ::cryptoki_tests::test_with_hsm
            },
            quote! {
                fn test_impl(#parameters)
            },
        ),
        ReturnType::Type(_, ref t) => {
            let ret = t.to_token_stream();
            (
                quote! {
                    ::cryptoki_tests::test_with_hsm_result
                },
                quote! {
                    fn test_impl(#parameters) -> #ret
                },
            )
        }
    };
    input.sig.output = ReturnType::Default;

    // Then we'll grab the test body block, put that in the inner function
    // and replace the outer function with a wrapper
    let body = input.block;

    input.block = syn::parse_quote! {
        {
            #test_impl_sig #body

            #tester(test_impl)
        }
    };

    let output = quote! {
        #header
        #input
    };

    Ok(output.into())
}
