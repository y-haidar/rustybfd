use rustybfd::socket::test_impl::serve;

#[tokio::main]
async fn main() {
  serve().await.unwrap();
}
