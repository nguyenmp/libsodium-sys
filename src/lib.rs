#[cfg(test)]
mod tests {
    #[test]
    fn foo_and_bar_are_equal() {
        assert_eq!(super::bar(), super::foo());
    }
}

fn bar() -> &'static str {
    "asdff"
}

pub fn foo() -> &'static str {
    bar()
}