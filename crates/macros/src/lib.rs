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

#[proc_macro_derive(Patch)]
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
                    "Patch derive only supports structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(name, "Patch derive only supports structs")
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
            #vis #field_name: crate::crd::Patch<#inner_ty>
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
