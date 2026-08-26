use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, GenericArgument, PathArguments, Type, parse_macro_input};

/// Helper to unwrap `Option<T>` into `T` if the type is `Option<T>`.
fn unwrap_option_type(ty: &Type) -> &Type {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Option"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && let Some(GenericArgument::Type(inner_type)) = args.args.first()
    {
        return inner_type;
    }
    ty
}

#[proc_macro_derive(PatchValue)]
pub fn derive_patch(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let patch_name = quote::format_ident!("{}Patch", name);

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return syn::Error::new_spanned(
                    name,
                    "PatchValue derive only supports structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(name, "PatchValue derive only supports structs")
                .to_compile_error()
                .into();
        }
    };

    let patch_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        let vis = &f.vis;
        let attrs = f.attrs.iter().filter(|attr| !attr.path().is_ident("serde"));
        let inner_ty = unwrap_option_type(&f.ty);

        quote! {
            #(#attrs)*
            #[serde(default)]
            #vis #field_name: crate::crd::PatchValue<#inner_ty>
        }
    });

    let expanded = quote! {
        #[derive(Debug, serde::Serialize, serde::Deserialize, Default, Clone, schemars::JsonSchema, PartialEq)]
        #[serde(rename_all = "camelCase")]
        pub struct #patch_name {
            #(#patch_fields,)*
        }
    };

    TokenStream::from(expanded)
}

fn is_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return segment.ident == "String";
    }
    false
}

fn extract_named_fields<'a>(
    input: &'a DeriveInput,
    macro_name: &str,
) -> Result<&'a syn::punctuated::Punctuated<syn::Field, syn::token::Comma>, syn::Error> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(&fields.named),
            _ => Err(syn::Error::new_spanned(
                &input.ident,
                format!("{macro_name} derive only supports structs with named fields"),
            )),
        },
        _ => Err(syn::Error::new_spanned(
            &input.ident,
            format!("{macro_name} derive only supports structs"),
        )),
    }
}

#[proc_macro_derive(BorrowedKey)]
pub fn derive_borrowed_key(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let vis = &input.vis;
    let ref_name = quote::format_ident!("{}Ref", name);

    let fields = match extract_named_fields(&input, "BorrowedKey") {
        Ok(f) => f,
        Err(err) => return err.to_compile_error().into(),
    };

    let field_names: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let field_vis: Vec<_> = fields.iter().map(|f| &f.vis).collect();

    let ref_field_types: Vec<_> = fields
        .iter()
        .map(|f| {
            let ty = &f.ty;
            if is_string_type(ty) {
                quote! { &'a str }
            } else {
                quote! { &'a #ty }
            }
        })
        .collect();

    let expanded = quote! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #vis struct #ref_name<'a> {
            #( #field_vis #field_names: #ref_field_types, )*
        }

        impl #name {
            pub fn as_ref(&self) -> #ref_name<'_> {
                #ref_name {
                    #( #field_names: &self.#field_names, )*
                }
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(BorrowedHash)]
pub fn derive_borrowed_hash(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let ref_name = quote::format_ident!("{}Ref", name);

    let fields = match extract_named_fields(&input, "BorrowedHash") {
        Ok(f) => f,
        Err(err) => return err.to_compile_error().into(),
    };

    let field_names: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();

    let expanded = quote! {
        impl<'a> std::hash::Hash for #ref_name<'a> {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                #( self.#field_names.hash(state); )*
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Equivalent)]
pub fn derive_equivalent(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let ref_name = quote::format_ident!("{}Ref", name);

    let fields = match extract_named_fields(&input, "Equivalent") {
        Ok(f) => f,
        Err(err) => return err.to_compile_error().into(),
    };

    let field_names: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();

    let expanded = quote! {
        impl<'a> hashbrown::Equivalent<#name> for #ref_name<'a> {
            fn equivalent(&self, key: &#name) -> bool {
                #( self.#field_names == key.#field_names )&&*
            }
        }
    };

    TokenStream::from(expanded)
}
