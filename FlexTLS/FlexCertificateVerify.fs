#light "off"

module FlexCertificateVerify

open FlexTypes
open FlexConstants




type FlexCertificateVerify = 
    class
    
    static member receive (st:state) : state * FCertificateVerify =
        st,nullFCertificateVerify

    static member send (st:state) : state * FCertificateVerify =
        st,nullFCertificateVerify

    end
