//! The `#[identity_attributes]` attribute. Use it through the
//! `identity-attributes` crate, which re-exports it and holds the code it
//! calls.

use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, FnArg, ItemFn};

/// Marks the function that receives every verified attribute bundle, and adds
/// `_internet_identity_sign_in_start` and `_internet_identity_sign_in_finish`
/// to the canister.
///
/// The function takes the caller's `Principal` and their `IdentityAttributes`,
/// and is called only for a bundle that passes every check:
///
/// ```ignore
/// use candid::Principal;
/// use identity_attributes::{identity_attributes, IdentityAttributes};
///
/// #[identity_attributes]
/// fn consume_attributes(caller: Principal, attributes: IdentityAttributes) {
///     // store `attributes` for `caller` however the app needs
/// }
/// ```
#[proc_macro_attribute]
pub fn identity_attributes(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = proc_macro2::TokenStream::from(attr);
    let function = parse_macro_input!(item as ItemFn);
    match expand(args, function) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn expand(
    args: proc_macro2::TokenStream,
    function: ItemFn,
) -> syn::Result<proc_macro2::TokenStream> {
    check(&args, &function)?;
    let name = &function.sig.ident;
    // The generated methods name the runtime crate and `ic_cdk` without a
    // leading `::`, because `ic_cdk::export_candid!` re-parses their
    // signatures and does not accept one.
    Ok(quote! {
        #function

        #[ic_cdk::update]
        async fn _internet_identity_sign_in_start() -> Vec<u8> {
            identity_attributes::sign_in_start().await
        }

        #[ic_cdk::update]
        fn _internet_identity_sign_in_finish() -> identity_attributes::SignInResult {
            identity_attributes::sign_in_finish(#name)
        }
    })
}

/// The attribute takes no arguments, and the function is a plain one taking
/// the caller and their attributes.
fn check(args: &proc_macro2::TokenStream, function: &ItemFn) -> syn::Result<()> {
    if !args.is_empty() {
        return Err(syn::Error::new(
            args.span(),
            "#[identity_attributes] takes no arguments",
        ));
    }
    let sig = &function.sig;
    if let Some(asyncness) = sig.asyncness {
        return Err(syn::Error::new(
            asyncness.span(),
            "the #[identity_attributes] function cannot be async: it runs inside the sign-in call",
        ));
    }
    if !sig.generics.params.is_empty() {
        return Err(syn::Error::new(
            sig.generics.span(),
            "the #[identity_attributes] function cannot be generic",
        ));
    }
    if let Some(FnArg::Receiver(receiver)) = sig.inputs.first() {
        return Err(syn::Error::new(
            receiver.span(),
            "the #[identity_attributes] function cannot take `self`",
        ));
    }
    if sig.inputs.len() != 2 {
        return Err(syn::Error::new(
            sig.inputs.span(),
            "the #[identity_attributes] function takes two arguments: the caller's `Principal` and their `IdentityAttributes`",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn checked(
        args: proc_macro2::TokenStream,
        function: proc_macro2::TokenStream,
    ) -> Result<(), String> {
        let function: ItemFn = syn::parse2(function).unwrap();
        check(&args, &function).map_err(|e| e.to_string())
    }

    #[test]
    fn accepts_a_plain_function_of_two_arguments() {
        assert_eq!(
            checked(
                quote!(),
                quote!(
                    fn consume(caller: Principal, attributes: IdentityAttributes) {}
                )
            ),
            Ok(())
        );
    }

    #[test]
    fn refuses_arguments_to_the_attribute() {
        assert!(checked(
            quote!(foo),
            quote!(
                fn consume(a: A, b: B) {}
            )
        )
        .unwrap_err()
        .contains("takes no arguments"));
    }

    #[test]
    fn refuses_an_async_function() {
        assert!(checked(
            quote!(),
            quote!(
                async fn consume(a: A, b: B) {}
            )
        )
        .unwrap_err()
        .contains("cannot be async"));
    }

    #[test]
    fn refuses_a_generic_function() {
        assert!(checked(
            quote!(),
            quote!(
                fn consume<T>(a: A, b: T) {}
            )
        )
        .unwrap_err()
        .contains("cannot be generic"));
    }

    #[test]
    fn refuses_the_wrong_number_of_arguments() {
        for function in [
            quote!(
                fn consume() {}
            ),
            quote!(
                fn consume(a: A) {}
            ),
            quote!(
                fn consume(a: A, b: B, c: C) {}
            ),
        ] {
            assert!(checked(quote!(), function)
                .unwrap_err()
                .contains("takes two arguments"));
        }
    }

    #[test]
    fn generates_both_methods_calling_the_function() {
        let function: ItemFn = syn::parse2(quote!(
            fn consume(a: A, b: B) {}
        ))
        .unwrap();
        let expanded = expand(quote!(), function).unwrap().to_string();
        assert!(expanded.contains("fn consume"));
        assert!(expanded.contains("async fn _internet_identity_sign_in_start"));
        assert!(expanded.contains("fn _internet_identity_sign_in_finish"));
        assert!(expanded.contains("sign_in_finish (consume)"));
    }
}
