class CodeAllocator {
  constructor (sliceSize) {
    this.sliceSize = sliceSize;
    this.slicesPerPage = Process.pageSize / sliceSize;

    this.pages = [];
    this.free = [];
  }

  allocateSlice () {
    let slice = this.free.pop();
    if (slice !== undefined) {
      return slice;
    }

    return this._allocatePage();
  }

  _allocatePage () {
    const page = Memory.alloc(Process.pageSize);
    for (let i = 1; i < this.slicesPerPage; i++) {
      const slice = page.add(this.sliceSize * i);
      this.free.push(slice);
    }

    this.pages.push(page);

    return page;
  }

  freeSlice (slice) {
    this.free.push(slice);
  }
}

function makeAllocator (sliceSize) {
    return new CodeAllocator(sliceSize);
}

module.exports = makeAllocator;
