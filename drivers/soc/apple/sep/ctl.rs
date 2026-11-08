// SPDX-License-Identifier: GPL-2.0-only
//
// The control endpoint's request in flight. macOS's AppleSEPManager sends each control request with a tag and takes
// the SEP's ack, op 0x01 with the same tag and the data echoed, as its answer (sep-1.log 1531-1785). The lab sends
// one at a time, with macOS's tags (proto::STAGE1 and on), so one slot holds the request and its answer; a tagged
// message that answers nothing in flight is logged and dropped, and the first missing answer ends the sequence, so
// no tag is reused after a lost one.

use crate::proto::Word;

pub(crate) struct Slot {
    sent: Option<Word>,
    answer: Option<Word>,
}

impl Slot {
    pub(crate) const fn new() -> Slot {
        Slot { sent: None, answer: None }
    }

    /// Records `req` as the request in flight; false if one already is.
    pub(crate) fn arm(&mut self, req: Word) -> bool {
        if self.sent.is_some() {
            return false;
        }
        self.sent = Some(req);
        self.answer = None;
        true
    }

    /// A tagged message on the control endpoint: kept, and true, when it is the first with the tag in flight.
    pub(crate) fn offer(&mut self, w: Word) -> bool {
        let fits = matches!(self.sent, Some(r) if r.tag == w.tag) && self.answer.is_none();
        if fits {
            self.answer = Some(w);
        }
        fits
    }

    pub(crate) fn take(&mut self) -> Option<Word> {
        self.answer.take()
    }

    pub(crate) fn disarm(&mut self) {
        self.sent = None;
        self.answer = None;
    }
}
