# diffida
Rust application based on schnorrkel verification

### Local testing
This application is hosted on [https://www.shuttle.rs/](https://www.shuttle.rs/) if you want to test it locally you can run:
```sh
❯ cargo shuttle run
```

### Endpoints
All details are also avaialble calling the `/doc` method

| Endpoint | Description |
|---|---|
| `/doc` | Return the swagger API definition in text/plain |
| `/api/generate` | Generates mnemonic |
| `/api/sign` | Sign your message |
| `/api/verify` | Verify your message |

### License
```
Copyright 2023 Marco Cattaneo  
 
Licensed under the Apache License, Version 2.0 (the "License");  
you may not use this file except in compliance with the License.  
You may obtain a copy of the License at  
 
     https://www.apache.org/licenses/LICENSE-2.0  
 
Unless required by applicable law or agreed to in writing, software  
distributed under the License is distributed on an "AS IS" BASIS,  
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
See the License for the specific language governing permissions and  
limitations under the License.
```